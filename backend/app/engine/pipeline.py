"""日志处理管道：归一化 -> GeoIP 富化 -> 规则匹配 -> 告警聚合 -> 落库。"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from app.engine.aggregator import AlertAggregator, ThresholdCounter
from app.engine.geoip import GeoIPResolver
from app.engine.matcher import RuleEngine, RuleHit, format_description, get_field_value
from app.engine.rule_loader import RuleLoader
from app.models.schemas import AlertSample, IngestEvent, IngestResponse, LogEvent, Rule
from app.normalize.parsers import build_event
from app.storage import StorageBackend

logger = logging.getLogger(__name__)

MAX_SAMPLES = 10


class IngestPipeline:
    """采集管道核心类，串起解析、检测与存储。"""

    def __init__(
        self,
        storage: StorageBackend,
        loader: RuleLoader,
        engine: RuleEngine,
        aggregator: AlertAggregator,
        geoip: GeoIPResolver,
    ) -> None:
        """注入各依赖组件。"""
        self.storage = storage
        self.loader = loader
        self.engine = engine
        self.aggregator = aggregator
        self.geoip = geoip
        self.counter = ThresholdCounter()

    def reload_rules(self) -> int:
        """重新加载规则并同步到匹配引擎，返回启用规则数量。"""
        rules = self.loader.load()
        self.engine.set_rules(rules)
        return len(self.engine.rules)

    # ---------------- 主流程 ----------------

    async def process(
        self, host: str, source_type: str, events: list[IngestEvent]
    ) -> IngestResponse:
        """处理一批上报事件，返回接收条数与产生/合并的告警数。"""
        geo_cache: dict[str, Any] = {}
        docs: list[tuple[str, dict[str, Any]]] = []
        alert_count = 0
        accepted = 0

        for item in events:
            try:
                event = build_event(host, source_type, item.raw, item.fields)
            except Exception as exc:  # 单条解析异常不影响整批数据
                logger.warning("事件归一化失败，已跳过: %s", exc)
                continue
            if item.timestamp:
                event.timestamp = item.timestamp
            accepted += 1

            if event.src_ip and event.src_ip not in geo_cache:
                geo_cache[event.src_ip] = await self.geoip.resolve(event.src_ip)
            if event.src_ip and geo_cache.get(event.src_ip):
                event.geo = geo_cache[event.src_ip]

            hits = self.engine.evaluate(event)
            for hit in hits:
                created = await self._handle_hit(hit, geo_cache)
                if created:
                    alert_count += 1
                event.matched_rules.append(hit.rule.id)
                event.tags = sorted(set(event.tags) | set(hit.rule.tags))

            docs.append((self.storage.log_index_for(event.timestamp), event.es_doc()))

        if docs:
            await self.storage.bulk_index_logs(docs)
        return IngestResponse(accepted=accepted, alerts=alert_count)

    async def _handle_hit(self, hit: RuleHit, geo_cache: dict[str, Any]) -> bool:
        """处理单次规则命中：阈值判断、首次出现判断、告警创建/合并。"""
        rule = hit.rule
        event = hit.event

        if self.aggregator.should_suppress(rule, event.src_ip):
            return False

        group_key = self.aggregator.build_group_key(rule, hit.groups)
        # 若该分组已处于冷却窗口内（同一攻击仍在持续），直接合并进已有告警而不再计数，
        # 避免持续攻击每隔 N 次就新产生一条重复告警。
        in_cooldown = self.aggregator.active_alert_id(rule.id, group_key, event.timestamp) is not None

        if rule.type == "threshold" and rule.threshold and not in_cooldown:
            count = self.counter.add(rule.id, group_key, event.timestamp, rule.threshold.window)
            if count < rule.threshold.count:
                return False
            self.counter.reset(rule.id, group_key)

        if rule.type == "first_seen" and not await self._is_first_seen(rule, hit):
            return False

        description = format_description(rule, hit)
        if rule.type == "threshold" and rule.threshold:
            description = f"{description}（{rule.threshold.window} 秒内累计 {rule.threshold.count} 次，分组 {group_key}）"

        sample = AlertSample(
            timestamp=event.timestamp,
            host=event.host,
            src_ip=event.src_ip,
            raw=(event.raw or event.message)[:1000],
        )
        fields = {
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "host": event.host,
            "user": event.user or hit.extracted.get("user"),
        }
        geo = geo_cache.get(event.src_ip) if event.src_ip else None
        _, is_new = await self.aggregator.open_or_update(
            storage=self.storage,
            rule=rule,
            group_key=group_key,
            fields=fields,
            description=description,
            sample=sample,
            timestamp=event.timestamp,
            geo=geo.model_dump() if geo else None,
        )
        return is_new

    async def _is_first_seen(self, rule: Rule, hit: RuleHit) -> bool:
        """判断“该组合是否首次出现”，用于识别异常登录（新 IP/新账号）。"""
        fields = [f.strip() for f in rule.first_seen_field.split(",") if f.strip()]
        must: list[dict[str, Any]] = []
        for field in fields:
            value = get_field_value(hit.event, field, hit.extracted)
            if not value:
                return False
            must.append({"term": {field: value}})

        since = hit.event.timestamp - timedelta(seconds=rule.first_seen_lookback)
        query = {
            "bool": {
                "filter": [
                    {"bool": {"must": must}},
                    {"range": {"@timestamp": {"gte": since.isoformat(), "lt": hit.event.timestamp.isoformat()}}},
                ]
            }
        }
        try:
            seen = await self.storage.count(self.storage.log_index_pattern, query)
        except Exception as exc:  # 查询失败时保守处理，不误报
            logger.warning("首次出现检测查询失败: %s", exc)
            return False
        return seen == 0

    # ---------------- 维护 ----------------

    def prune_state(self) -> None:
        """定期清理内存态（阈值计数、冷却记录）。"""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        self.counter.prune(now - timedelta(hours=1))
        self.aggregator.prune()

"""告警聚合、去重与降噪模块。

降噪策略：
1. 白名单 / 内网源抑制：命中全局白名单或规则白名单的源 IP 不产生告警；
2. 等级过滤：低于 MIN_ALERT_SEVERITY 的告警直接丢弃；
3. 冷却窗口合并：同一规则 + 同一分组在冷却窗口内只保留一条告警，命中次数累加（去重聚合）；
4. 阈值计数：频率类规则在滑动窗口内计数，达到阈值才告警，避免单条噪音刷屏。
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from app.models.schemas import Alert, AlertSample, Rule
from app.storage import StorageBackend
from app.utils.net import is_internal_ip

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_GROUP_FIELDS = ["src_ip"]


class ThresholdCounter:
    """滑动窗口计数器：按 (规则, 分组) 统计窗口内命中次数。"""

    def __init__(self) -> None:
        """初始化计数状态容器。"""
        self._buckets: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)

    def add(self, rule_id: str, group_key: str, ts: datetime, window: int) -> int:
        """记录一次命中并返回窗口内累计次数（自动淘汰过期记录）。"""
        key = (rule_id, group_key)
        bucket = self._buckets[key]
        cutoff = ts - timedelta(seconds=window)
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc))
        return len(bucket)

    def reset(self, rule_id: str, group_key: str) -> None:
        """达到阈值告警后清空计数，避免同一次攻击反复触发。"""
        self._buckets.pop((rule_id, group_key), None)

    def prune(self, older_than: datetime) -> None:
        """清理长期无活动的计数桶，防止内存增长。"""
        for key in list(self._buckets.keys()):
            bucket = self._buckets[key]
            while bucket and bucket[0] < older_than:
                bucket.popleft()
            if not bucket:
                self._buckets.pop(key, None)


class AlertAggregator:
    """告警聚合器：负责抑制判断、冷却合并与告警落库。"""

    def __init__(
        self,
        cooldown: int,
        whitelist: set[str],
        ignore_internal: bool,
        min_severity: str,
    ) -> None:
        """初始化降噪参数与内存中的冷却状态。"""
        self.cooldown = cooldown
        self.whitelist = whitelist
        self.ignore_internal = ignore_internal
        self.min_severity = min_severity
        # (rule_id, group_key) -> {"id": 告警ID, "expire": 过期时间}
        self._active: dict[tuple[str, str], dict[str, Any]] = {}

    # ---------------- 抑制判断 ----------------

    def should_suppress(self, rule: Rule, event_src_ip: str | None) -> bool:
        """判断该事件是否应被抑制（白名单、内网、等级不足）。"""
        if SEVERITY_ORDER.get(rule.severity, 2) < SEVERITY_ORDER.get(self.min_severity, 1):
            return True
        if not event_src_ip:
            return False
        if event_src_ip in self.whitelist or event_src_ip in set(rule.suppression.ignore_ips):
            return True
        if (self.ignore_internal or rule.suppression.ignore_internal) and is_internal_ip(event_src_ip):
            return True
        return False

    def cooldown_for(self, rule: Rule) -> int:
        """返回规则生效的冷却秒数。"""
        return rule.suppression.cooldown or self.cooldown

    # ---------------- 聚合 ----------------

    @staticmethod
    def build_group_key(rule: Rule, groups: dict[str, str]) -> str:
        """构造分组键，用于判断两次命中是否属于同一类事件。"""
        fields = (rule.threshold.group_by if rule.threshold else None) or DEFAULT_GROUP_FIELDS
        parts = [f"{f}={groups.get(f, '-')}" for f in fields]
        extra = [f"{k}={v}" for k, v in sorted(groups.items()) if k not in fields]
        return "|".join(parts + extra) or "default"

    def active_alert_id(self, rule_id: str, group_key: str, now: datetime) -> str | None:
        """查询冷却窗口内是否已有同组告警，有则返回其 ID（供聚合合并使用）。"""
        item = self._active.get((rule_id, group_key))
        if not item:
            return None
        if item["expire"] < now:
            self._active.pop((rule_id, group_key), None)
            return None
        return item["id"]

    async def open_or_update(
        self,
        storage: StorageBackend,
        rule: Rule,
        group_key: str,
        fields: dict[str, Any],
        description: str,
        sample: AlertSample,
        timestamp: datetime,
        geo: dict[str, Any] | None,
    ) -> tuple[str, bool]:
        """创建新告警或合并到冷却窗口内的已有告警，返回 (告警ID, 是否新建)。"""
        now = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
        existing = self.active_alert_id(rule.id, group_key, now)
        cooldown = self.cooldown_for(rule)

        if existing:
            await storage.increment_alert(
                existing, count=1, last_seen=now, sample=sample.model_dump(mode="json")
            )
            self._active[(rule.id, group_key)] = {
                "id": existing,
                "expire": now + timedelta(seconds=cooldown),
            }
            return existing, False

        alert = Alert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            status="open",
            first_seen=now,
            last_seen=now,
            count=1,
            group_key=group_key,
            src_ip=fields.get("src_ip"),
            dst_ip=fields.get("dst_ip"),
            host=fields.get("host"),
            user=fields.get("user"),
            description=description,
            tags=list(rule.tags),
            samples=[sample],
            geo=geo,  # type: ignore[arg-type]
        )
        alert_id = await storage.index_alert(alert.model_dump(mode="json", exclude={"id"}))
        self._active[(rule.id, group_key)] = {
            "id": alert_id,
            "expire": now + timedelta(seconds=cooldown),
        }
        return alert_id, True

    def prune(self) -> None:
        """清理已过期的冷却记录。"""
        now = datetime.now(timezone.utc)
        for key in [k for k, v in self._active.items() if v["expire"] < now]:
            self._active.pop(key, None)

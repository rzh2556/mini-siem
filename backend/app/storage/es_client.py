"""Elasticsearch 存储层：负责索引模板初始化、日志/告警的写入与检索。"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from elasticsearch import AsyncElasticsearch, NotFoundError

logger = logging.getLogger(__name__)

# 日志索引 mapping：字符串统一使用 keyword 便于聚合，正文类字段使用 text
LOG_MAPPING: dict[str, Any] = {
    "properties": {
        "@timestamp": {"type": "date"},
        "host": {"type": "keyword"},
        "source_type": {"type": "keyword"},
        "level": {"type": "keyword"},
        "src_ip": {"type": "keyword"},
        "dst_ip": {"type": "keyword"},
        "src_port": {"type": "integer"},
        "dst_port": {"type": "integer"},
        "user": {"type": "keyword"},
        "method": {"type": "keyword"},
        "url": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
        "path": {"type": "keyword"},
        "query": {"type": "text"},
        "status_code": {"type": "integer"},
        "user_agent": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
        "event_id": {"type": "integer"},
        "channel": {"type": "keyword"},
        "process": {"type": "keyword"},
        "command": {"type": "text"},
        "message": {"type": "text"},
        "raw": {"type": "text", "index": False},
        "tags": {"type": "keyword"},
        "matched_rules": {"type": "keyword"},
        "geo": {
            "properties": {
                "country": {"type": "keyword"},
                "country_code": {"type": "keyword"},
                "city": {"type": "keyword"},
                "lat": {"type": "double"},
                "lon": {"type": "double"},
            }
        },
    }
}

# 告警索引 mapping，samples 不建索引仅用于展示
ALERT_MAPPING: dict[str, Any] = {
    "properties": {
        "rule_id": {"type": "keyword"},
        "rule_name": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "status": {"type": "keyword"},
        "first_seen": {"type": "date"},
        "last_seen": {"type": "date"},
        "created_at": {"type": "date"},
        "updated_at": {"type": "date"},
        "count": {"type": "integer"},
        "group_key": {"type": "keyword"},
        "src_ip": {"type": "keyword"},
        "dst_ip": {"type": "keyword"},
        "host": {"type": "keyword"},
        "user": {"type": "keyword"},
        "description": {"type": "text"},
        "tags": {"type": "keyword"},
        "ack_comment": {"type": "text"},
        "samples": {"type": "object", "enabled": False},
        "geo": {
            "properties": {
                "country": {"type": "keyword"},
                "country_code": {"type": "keyword"},
                "city": {"type": "keyword"},
                "lat": {"type": "double"},
                "lon": {"type": "double"},
            }
        },
    }
}


class ESStorage:
    """Elasticsearch 异步客户端封装。"""

    def __init__(self, url: str, prefix: str, retention_days: int = 30) -> None:
        """初始化客户端参数。"""
        self.url = url
        self.prefix = prefix
        self.retention_days = retention_days
        self.client = AsyncElasticsearch(hosts=[url], request_timeout=30, retry_on_timeout=True)

    # ---------------- 生命周期 ----------------

    async def ping(self) -> bool:
        """检查 Elasticsearch 是否可用。"""
        try:
            return bool(await self.client.ping())
        except Exception:  # 网络异常时视为不可用
            return False

    async def close(self) -> None:
        """关闭客户端连接。"""
        await self.client.close()

    async def ensure_indices(self) -> None:
        """创建日志索引模板、告警索引与生命周期策略（幂等）。"""
        await self.client.indices.put_index_template(
            name=f"{self.prefix}-logs-template",
            index_patterns=[f"{self.prefix}-logs-*"],
            template={"settings": self._index_settings(), "mappings": LOG_MAPPING},
        )
        if not await self.client.indices.exists(index=self.alert_index):
            await self.client.indices.create(
                index=self.alert_index,
                settings=self._index_settings(),
                mappings=ALERT_MAPPING,
            )
        logger.info("Elasticsearch 索引初始化完成")

    def _index_settings(self) -> dict[str, Any]:
        """返回索引通用设置（分片、刷新间隔）。"""
        return {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "5s",
        }

    @property
    def alert_index(self) -> str:
        """告警索引名。"""
        return f"{self.prefix}-alerts"

    @property
    def log_index_pattern(self) -> str:
        """日志索引通配符。"""
        return f"{self.prefix}-logs-*"

    def log_index_for(self, ts: datetime | None = None) -> str:
        """按时间计算日志索引名（按天切分）。"""
        ts = ts or datetime.now(timezone.utc)
        return f"{self.prefix}-logs-{ts.strftime('%Y.%m.%d')}"

    # ---------------- 写入 ----------------

    async def bulk_index_logs(self, docs: list[tuple[str, dict[str, Any]]]) -> int:
        """批量写入日志文档，参数为 (索引名, 文档) 列表，返回成功条数。"""
        if not docs:
            return 0
        operations: list[dict[str, Any]] = []
        for index_name, doc in docs:
            operations.append({"index": {"_index": index_name}})
            operations.append(doc)
        resp = await self.client.bulk(operations=operations)
        if resp.get("errors"):
            failed = sum(1 for item in resp["items"] if item.get("index", {}).get("error"))
            logger.warning("批量写入存在 %s 条失败记录", failed)
        return len(docs)

    async def index_alert(self, doc: dict[str, Any], alert_id: str | None = None) -> str:
        """写入或覆盖一条告警，返回告警 ID。"""
        resp = await self.client.index(
            index=self.alert_index,
            id=alert_id,
            document=doc,
            refresh="wait_for",
        )
        return resp["_id"]

    async def update_alert(self, alert_id: str, doc: dict[str, Any]) -> bool:
        """局部更新告警文档，文档不存在时返回 False。"""
        try:
            await self.client.update(
                index=self.alert_index, id=alert_id, doc=doc, refresh="wait_for"
            )
            return True
        except NotFoundError:
            return False

    async def increment_alert(
        self, alert_id: str, count: int, last_seen: datetime, sample: dict[str, Any] | None
    ) -> bool:
        """对已有告警执行计数累加、刷新时间并追加样本（用于告警聚合）。"""
        script = {
            "source": (
                "ctx._source.count += params.c;"
                "ctx._source.last_seen = params.ls;"
                "ctx._source.updated_at = params.ls;"
                "if (params.sample != null) {"
                "  if (ctx._source.samples == null) { ctx._source.samples = []; }"
                "  if (ctx._source.samples.size() < 10) { ctx._source.samples.add(params.sample); }"
                "}"
            ),
            "lang": "painless",
            "params": {
                "c": count,
                "ls": last_seen.isoformat(),
                "sample": sample,
            },
        }
        try:
            await self.client.update(
                index=self.alert_index, id=alert_id, script=script, refresh="wait_for"
            )
            return True
        except NotFoundError:
            return False

    # ---------------- 查询 ----------------

    async def search(
        self,
        index: str,
        query: dict[str, Any] | None = None,
        sort: list[Any] | None = None,
        page: int = 1,
        size: int = 20,
        aggs: dict[str, Any] | None = None,
        source: list[str] | None = None,
    ) -> dict[str, Any]:
        """通用检索，返回原始 ES 响应。"""
        body: dict[str, Any] = {
            "query": query or {"match_all": {}},
            "from": max(0, (page - 1) * size),
            "size": size,
            "track_total_hits": True,
        }
        if sort:
            body["sort"] = sort
        if aggs:
            body["aggs"] = aggs
        if source:
            body["_source"] = source
        return await self.client.search(index=index, **body)

    async def count(self, index: str, query: dict[str, Any] | None = None) -> int:
        """统计满足条件的文档数。"""
        resp = await self.client.count(index=index, query=query or {"match_all": {}})
        return int(resp.get("count", 0))

    async def get_doc(self, index: str, doc_id: str) -> dict[str, Any] | None:
        """按 ID 获取文档，不存在返回 None。"""
        try:
            resp = await self.client.get(index=index, id=doc_id)
            return {"id": resp["_id"], **resp["_source"]}
        except NotFoundError:
            return None

    async def update_by_query(self, index: str, query: dict[str, Any], script: dict[str, Any]) -> int:
        """按条件批量更新，返回受影响条数。"""
        resp = await self.client.update_by_query(
            index=index, query=query, script=script, refresh=True, conflicts="proceed"
        )
        return int(resp.get("updated", 0))

    # ---------------- 维护 ----------------

    async def cleanup_old_indices(self) -> list[str]:
        """删除超过保留期的日志索引，返回被删除的索引名。"""
        if self.retention_days <= 0:
            return []
        indices = await self.client.indices.get(index=self.log_index_pattern, allow_no_indices=True)
        cutoff = datetime.now(timezone.utc).timestamp() - self.retention_days * 86400
        removed: list[str] = []
        for name in indices:
            suffix = name.rsplit("-", 1)[-1]
            try:
                ts = datetime.strptime(suffix, "%Y.%m.%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if ts.timestamp() < cutoff:
                await self.client.indices.delete(index=name, ignore_unavailable=True)
                removed.append(name)
        if removed:
            logger.info("已清理过期索引: %s", ", ".join(removed))
        return removed

"""SQLite 存储层：零外部依赖的轻量实现，用于替代 Elasticsearch 降低服务器负载。

设计要点：
1. 只使用标准库 sqlite3，无需额外服务与 JVM，常驻内存仅几 MB，适合 1-2 GB 内存的小服务器；
2. 对外暴露与 ESStorage 完全一致的方法签名与返回结构，上层 API、管道与前端无需改动；
3. 内部把项目实际用到的 Elasticsearch DSL 子集（term/terms/range/exists/bool/全文查询
   与 terms/date_histogram/sum/max 聚合）翻译成 SQL；
4. 所有 SQL 值均使用参数绑定，列名来自白名单映射，避免注入。
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

INTERVAL_RE = re.compile(r"^(\d+)([smhd])$")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
RANGE_OPS = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<"}

# 时间字段 -> (展示列, 用于比较与聚合的 epoch 列)
TIME_FIELDS: dict[str, tuple[str, str]] = {
    "@timestamp": ("ts", "ts_epoch"),
    "timestamp": ("ts", "ts_epoch"),
    "first_seen": ("first_seen", "first_seen_epoch"),
    "last_seen": ("last_seen", "last_seen_epoch"),
}

# Elasticsearch 字段名 -> SQLite 列名（白名单，未列出的字段不支持过滤）
FIELD_MAP: dict[str, str] = {
    "@timestamp": "ts",
    "timestamp": "ts",
    "host": "host",
    "source_type": "source_type",
    "level": "level",
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "src_port": "src_port",
    "dst_port": "dst_port",
    "user": "user_name",
    "method": "method",
    "url": "url",
    "path": "path",
    "query": "query_str",
    "status_code": "status_code",
    "user_agent": "user_agent",
    "event_id": "event_id",
    "channel": "channel",
    "process": "process_name",
    "command": "command",
    "message": "message",
    "raw": "raw",
    "tags": "tags",
    "matched_rules": "matched_rules",
    "geo.country": "geo_country",
    "geo.country_code": "geo_country_code",
    "geo.city": "geo_city",
    "geo.lat": "geo_lat",
    "geo.lon": "geo_lon",
    "rule_id": "rule_id",
    "rule_name": "rule_name",
    "severity": "severity",
    "status": "status",
    "description": "description",
    "ack_comment": "ack_comment",
    "group_key": "group_key",
    "count": "count",
    "first_seen": "first_seen",
    "last_seen": "last_seen",
    "batch_id": "batch_id",
}

# 日志表列定义（顺序即插入顺序）
LOG_COLUMNS = (
    "ts", "ts_epoch", "host", "source_type", "level",
    "src_ip", "dst_ip", "src_port", "dst_port",
    "user_name", "method", "url", "path", "query_str",
    "status_code", "user_agent", "event_id", "channel", "process_name", "command",
    "message", "raw", "tags", "matched_rules",
    "geo_country", "geo_country_code", "geo_city", "geo_lat", "geo_lon",
    "batch_id",
)

ALERT_COLUMNS = (
    "rule_id", "rule_name", "severity", "status",
    "first_seen", "first_seen_epoch", "last_seen", "last_seen_epoch",
    "count", "group_key", "src_ip", "dst_ip", "host", "user_name",
    "description", "ack_comment",
    "geo_country", "geo_country_code", "geo_city", "geo_lat", "geo_lon",
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ts_epoch INTEGER NOT NULL,
    host TEXT, source_type TEXT, level TEXT,
    src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
    user_name TEXT, method TEXT, url TEXT, path TEXT, query_str TEXT,
    status_code INTEGER, user_agent TEXT,
    event_id INTEGER, channel TEXT, process_name TEXT, command TEXT,
    message TEXT, raw TEXT, tags TEXT, matched_rules TEXT,
    geo_country TEXT, geo_country_code TEXT, geo_city TEXT, geo_lat REAL, geo_lon REAL,
    batch_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_host ON logs(host);
CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source_type);

CREATE TABLE IF NOT EXISTS upload_batches (
    batch_id TEXT PRIMARY KEY,
    filename TEXT, host TEXT, source_type TEXT,
    total INTEGER DEFAULT 0, accepted INTEGER DEFAULT 0, alerts INTEGER DEFAULT 0,
    size_bytes INTEGER DEFAULT 0, note TEXT,
    created_at TEXT, created_at_epoch INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_upload_batches_ts ON upload_batches(created_at_epoch);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT, rule_name TEXT, severity TEXT, status TEXT,
    first_seen TEXT, first_seen_epoch INTEGER, last_seen TEXT, last_seen_epoch INTEGER,
    count INTEGER DEFAULT 1, group_key TEXT,
    src_ip TEXT, dst_ip TEXT, host TEXT, user_name TEXT,
    description TEXT, ack_comment TEXT,
    geo_country TEXT, geo_country_code TEXT, geo_city TEXT, geo_lat REAL, geo_lon REAL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen_epoch);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
"""


def _to_epoch(value: Any) -> float:
    """把 ISO8601 时间字符串或数字转换成 Unix 秒。"""
    if isinstance(value, (int, float)):
        return float(value)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def _parse_interval(value: str) -> int:
    """把 10m / 1h / 1d 这类固定间隔转换成秒数，无法解析时按 1 小时处理。"""
    match = INTERVAL_RE.match((value or "").strip())
    if not match:
        return 3600
    return int(match.group(1)) * UNIT_SECONDS[match.group(2)]


def _escape_like(text: str) -> str:
    """转义 LIKE 通配符，保证用户输入被当作普通字符匹配。"""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _resolve_column(field: str) -> str | None:
    """把 ES 字段名解析成 SQLite 列名，未知字段返回 None。"""
    return FIELD_MAP.get(field)


def _fulltext_clause(text: str, fields: list[str]) -> tuple[str, list[Any]]:
    """把全文检索请求翻译成 LIKE 子句：不同词之间为 AND，同一词在多个字段间为 OR。"""
    columns: list[str] = []
    for field in fields or []:
        column = _resolve_column(field.split("^")[0].strip())
        if column and column not in columns:
            columns.append(column)
    tokens = [token for token in (text or "").split() if token]
    if not columns or not tokens:
        return "1=1", []
    clauses: list[str] = []
    params: list[Any] = []
    for token in tokens:
        conditions = " OR ".join(f"{column} LIKE ? ESCAPE '\\'" for column in columns)
        clauses.append(f"({conditions})")
        params.extend([f"%{_escape_like(token)}%"] * len(columns))
    return " AND ".join(clauses), params


def _translate_query(query: dict[str, Any] | None) -> tuple[str, list[Any]]:
    """把 Elasticsearch 查询 DSL 子集翻译成 SQL WHERE 子句与参数列表。"""
    if not query:
        return "1=1", []
    if "match_all" in query:
        return "1=1", []

    if "bool" in query:
        clauses: list[str] = []
        params: list[Any] = []
        for section in ("filter", "must"):
            for sub in query["bool"].get(section) or []:
                sql, sub_params = _translate_query(sub)
                clauses.append(f"({sql})")
                params.extend(sub_params)
        should = query["bool"].get("should") or []
        if should:
            options, option_params = [], []
            for sub in should:
                sql, sub_params = _translate_query(sub)
                options.append(f"({sql})")
                option_params.extend(sub_params)
            clauses.append("(" + " OR ".join(options) + ")")
            params.extend(option_params)
        return (" AND ".join(clauses) if clauses else "1=1"), params

    if "term" in query:
        field, value = next(iter(query["term"].items()))
        if field == "_id":
            return "id = ?", [value]
        column = _resolve_column(field)
        if column is None:
            return "1=1", []
        # 数组类字段（tags / matched_rules）以逗号分隔存储，需要用包含匹配
        if column in ("tags", "matched_rules"):
            return f"(',' || {column} || ',') LIKE ? ESCAPE '\\'", [f"%,{_escape_like(str(value))},%"]
        return f"{column} = ?", [value]

    if "terms" in query:
        field, values = next(iter(query["terms"].items()))
        column = "id" if field == "_id" else _resolve_column(field)
        values = list(values or [])
        if column is None or not values:
            return "1=1", []
        placeholders = ",".join("?" * len(values))
        return f"{column} IN ({placeholders})", values

    if "range" in query:
        field, bounds = next(iter(query["range"].items()))
        if field in TIME_FIELDS:
            column = TIME_FIELDS[field][1]
            is_time = True
        else:
            column = _resolve_column(field) or ""
            is_time = False
        parts: list[str] = []
        params: list[Any] = []
        for op, value in bounds.items():
            if op not in RANGE_OPS or column == "":
                continue
            parts.append(f"{column} {RANGE_OPS[op]} ?")
            params.append(_to_epoch(value) if is_time else value)
        return (" AND ".join(parts) if parts else "1=1"), params

    if "exists" in query:
        column = _resolve_column(query["exists"].get("field", ""))
        return (f"{column} IS NOT NULL" if column else "1=1"), []

    if "simple_query_string" in query:
        spec = query["simple_query_string"]
        return _fulltext_clause(spec.get("query", ""), spec.get("fields", []))

    if "multi_match" in query:
        spec = query["multi_match"]
        return _fulltext_clause(spec.get("query", ""), spec.get("fields", []))

    return "1=1", []


def _log_row_values(doc: dict[str, Any]) -> tuple[Any, ...]:
    """把日志文档拆解成日志表的列值元组。"""
    ts = doc.get("@timestamp") or doc.get("timestamp")
    geo = doc.get("geo") or {}
    row = {
        "ts": ts,
        "ts_epoch": int(_to_epoch(ts)) if ts else 0,
        "host": doc.get("host"),
        "source_type": doc.get("source_type"),
        "level": doc.get("level"),
        "src_ip": doc.get("src_ip"),
        "dst_ip": doc.get("dst_ip"),
        "src_port": doc.get("src_port"),
        "dst_port": doc.get("dst_port"),
        "user_name": doc.get("user"),
        "method": doc.get("method"),
        "url": doc.get("url"),
        "path": doc.get("path"),
        "query_str": doc.get("query"),
        "status_code": doc.get("status_code"),
        "user_agent": doc.get("user_agent"),
        "event_id": doc.get("event_id"),
        "channel": doc.get("channel"),
        "process_name": doc.get("process"),
        "command": doc.get("command"),
        "message": doc.get("message"),
        "raw": doc.get("raw"),
        "tags": ",".join(doc.get("tags") or []),
        "matched_rules": ",".join(doc.get("matched_rules") or []),
        "geo_country": geo.get("country"),
        "geo_country_code": geo.get("country_code"),
        "geo_city": geo.get("city"),
        "geo_lat": geo.get("lat"),
        "geo_lon": geo.get("lon"),
        "batch_id": doc.get("batch_id"),
    }
    return tuple(row[column] for column in LOG_COLUMNS)


def _alert_row_values(doc: dict[str, Any]) -> dict[str, Any]:
    """把告警文档中用于索引与过滤的字段提取成字典。"""
    first_seen = doc.get("first_seen")
    last_seen = doc.get("last_seen")
    geo = doc.get("geo") or {}
    return {
        "rule_id": doc.get("rule_id"),
        "rule_name": doc.get("rule_name"),
        "severity": doc.get("severity"),
        "status": doc.get("status"),
        "first_seen": first_seen,
        "first_seen_epoch": int(_to_epoch(first_seen)) if first_seen else None,
        "last_seen": last_seen,
        "last_seen_epoch": int(_to_epoch(last_seen)) if last_seen else None,
        "count": doc.get("count", 1),
        "group_key": doc.get("group_key"),
        "src_ip": doc.get("src_ip"),
        "dst_ip": doc.get("dst_ip"),
        "host": doc.get("host"),
        "user_name": doc.get("user"),
        "description": doc.get("description"),
        "ack_comment": doc.get("ack_comment"),
        "geo_country": geo.get("country"),
        "geo_country_code": geo.get("country_code"),
        "geo_city": geo.get("city"),
        "geo_lat": geo.get("lat"),
        "geo_lon": geo.get("lon"),
    }


def _row_to_log(row: sqlite3.Row) -> dict[str, Any]:
    """把日志表的一行还原成与 ES _source 一致的文档结构。"""
    doc: dict[str, Any] = {"@timestamp": row["ts"]}
    mapping = {
        "host": "host", "source_type": "source_type", "level": "level",
        "src_ip": "src_ip", "dst_ip": "dst_ip", "src_port": "src_port", "dst_port": "dst_port",
        "user_name": "user", "method": "method", "url": "url", "path": "path",
        "query_str": "query", "status_code": "status_code", "user_agent": "user_agent",
        "event_id": "event_id", "channel": "channel", "process_name": "process",
        "command": "command", "message": "message", "raw": "raw",
        "batch_id": "batch_id",
    }
    for column, field in mapping.items():
        value = row[column]
        if value is not None:
            doc[field] = value
    for column in ("tags", "matched_rules"):
        value = row[column]
        if value:
            doc[column] = [item for item in value.split(",") if item]
    if row["geo_lat"] is not None or row["geo_country_code"] or row["geo_country"]:
        geo: dict[str, Any] = {}
        for column, field in (
            ("geo_country", "country"),
            ("geo_country_code", "country_code"),
            ("geo_city", "city"),
            ("geo_lat", "lat"),
            ("geo_lon", "lon"),
        ):
            if row[column] is not None:
                geo[field] = row[column]
        doc["geo"] = geo
    return doc


class SQLiteStorage:
    """基于 SQLite 的日志与告警存储，接口与 ESStorage 保持一致。"""

    def __init__(self, path: str, prefix: str = "siem", retention_days: int = 30) -> None:
        """初始化数据库文件路径、索引前缀与数据保留天数。"""
        self.prefix = prefix
        self.retention_days = retention_days
        self.path = Path(path)
        if str(self.path.parent) not in ("", "."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # 可重入锁 + 单连接：SQLite 写入需串行化，避免 database is locked；
        # 使用 RLock 是因为 ensure_indices 会在已持锁的 _call 中再次进入 _init_schema
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    # ---------------- 内部工具 ----------------

    def _init_schema(self) -> None:
        """创建日志表、告警表与索引（幂等），并补齐老库缺失的列。"""
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """老版本数据库升级：为 logs 表补充 batch_id 列并建立索引（幂等）。

        注意：索引必须在补列之后创建。老库的 logs 表初始没有 batch_id 列，
        若在 SCHEMA_SQL 里直接建该索引会因缺列导致整个初始化失败。
        """
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(logs)")}
        if "batch_id" not in columns:
            self._conn.execute("ALTER TABLE logs ADD COLUMN batch_id TEXT")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_batch ON logs(batch_id)")

    async def _call(self, func, *args) -> Any:
        """在线程中加锁执行同步数据库操作，避免阻塞事件循环。"""

        def runner() -> Any:
            with self._lock:
                return func(*args)

        return await asyncio.to_thread(runner)

    def _table(self, index: str) -> str:
        """根据索引名判断目标表：告警索引走 alerts 表，其余走 logs 表。"""
        return "alerts" if index == self.alert_index else "logs"

    @property
    def alert_index(self) -> str:
        """告警索引名（保持与 ESStorage 一致的接口）。"""
        return f"{self.prefix}-alerts"

    @property
    def log_index_pattern(self) -> str:
        """日志索引通配符（保持与 ESStorage 一致的接口）。"""
        return f"{self.prefix}-logs-*"

    def log_index_for(self, ts: datetime | None = None) -> str:
        """返回日志所属的按天索引名，仅用于日志展示与清理统计。"""
        ts = ts or datetime.now(timezone.utc)
        return f"{self.prefix}-logs-{ts.strftime('%Y.%m.%d')}"

    # ---------------- 生命周期 ----------------

    async def ping(self) -> bool:
        """SQLite 为本地文件数据库，始终视为可用。"""
        return True

    async def close(self) -> None:
        """关闭数据库连接。"""
        await self._call(self._conn.close)

    async def ensure_indices(self) -> None:
        """确保表与索引存在（SQLite 版等价于建表）。"""
        await self._call(self._init_schema)

    # ---------------- 写入 ----------------

    async def bulk_index_logs(self, docs: list[tuple[str, dict[str, Any]]]) -> int:
        """批量写入日志文档，参数为 (索引名, 文档) 列表，返回写入条数。"""
        if not docs:
            return 0
        rows = [_log_row_values(doc) for _, doc in docs]
        return await self._call(self._bulk_index_logs_sync, rows)

    def _bulk_index_logs_sync(self, rows: list[tuple[Any, ...]]) -> int:
        """同步批量插入日志行。"""
        placeholders = ",".join("?" * len(LOG_COLUMNS))
        columns = ",".join(LOG_COLUMNS)
        self._conn.executemany(
            f"INSERT INTO logs ({columns}) VALUES ({placeholders})", rows
        )
        self._conn.commit()
        return len(rows)

    # ---------------- 上传批次与删除 ----------------

    async def record_upload_batch(self, meta: dict[str, Any]) -> str:
        """记录一次日志文件上传的批次信息，便于后续按批次查看与删除。"""
        return await self._call(self._record_upload_batch_sync, meta)

    def _record_upload_batch_sync(self, meta: dict[str, Any]) -> str:
        """同步写入批次元数据（同一 batch_id 覆盖更新）。"""
        batch_id = meta["batch_id"]
        self._conn.execute(
            "INSERT OR REPLACE INTO upload_batches "
            "(batch_id, filename, host, source_type, total, accepted, alerts, "
            " size_bytes, note, created_at, created_at_epoch) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                batch_id,
                meta.get("filename"),
                meta.get("host"),
                meta.get("source_type"),
                int(meta.get("total") or 0),
                int(meta.get("accepted") or 0),
                int(meta.get("alerts") or 0),
                int(meta.get("size_bytes") or 0),
                meta.get("note"),
                meta.get("created_at"),
                int(meta.get("created_at_epoch") or 0),
            ),
        )
        self._conn.commit()
        return batch_id

    async def list_upload_batches(self, page: int = 1, size: int = 20) -> dict[str, Any]:
        """分页列出上传批次（按上传时间倒序），并附带当前实际留存的日志条数。"""
        return await self._call(self._list_upload_batches_sync, page, size)

    def _list_upload_batches_sync(self, page: int, size: int) -> dict[str, Any]:
        """同步查询批次列表。"""
        total = int(self._conn.execute("SELECT COUNT(*) FROM upload_batches").fetchone()[0])
        rows = self._conn.execute(
            "SELECT * FROM upload_batches ORDER BY created_at_epoch DESC LIMIT ? OFFSET ?",
            [size, max(0, (page - 1) * size)],
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            # 实际留存条数实时统计，避免中途删除或写入失败导致与元数据不一致
            item["current"] = int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM logs WHERE batch_id = ?", [row["batch_id"]]
                ).fetchone()[0]
            )
            items.append(item)
        return {"total": total, "items": items}

    async def delete_upload_batch(self, batch_id: str) -> int:
        """删除某次上传的全部日志与批次记录，返回删除的日志条数。"""
        return await self._call(self._delete_upload_batch_sync, batch_id)

    def _delete_upload_batch_sync(self, batch_id: str) -> int:
        """同步按批次删除日志行。"""
        cursor = self._conn.execute("DELETE FROM logs WHERE batch_id = ?", [batch_id])
        removed = cursor.rowcount or 0
        self._conn.execute("DELETE FROM upload_batches WHERE batch_id = ?", [batch_id])
        self._conn.commit()
        return removed

    async def delete_log(self, log_id: str) -> bool:
        """按 ID 删除单条日志，日志不存在时返回 False。"""
        return await self._call(self._delete_log_sync, log_id)

    def _delete_log_sync(self, log_id: str) -> bool:
        """同步删除单条日志行。"""
        try:
            numeric_id = int(log_id)
        except (TypeError, ValueError):
            return False
        cursor = self._conn.execute("DELETE FROM logs WHERE id = ?", [numeric_id])
        self._conn.commit()
        return (cursor.rowcount or 0) > 0

    async def index_alert(self, doc: dict[str, Any], alert_id: str | None = None) -> str:
        """写入或覆盖一条告警，返回告警 ID。"""
        new_id = alert_id or uuid.uuid4().hex
        return await self._call(self._index_alert_sync, new_id, doc)

    def _index_alert_sync(self, alert_id: str, doc: dict[str, Any]) -> str:
        """同步写入告警行（存在则覆盖）。"""
        values = _alert_row_values(doc)
        columns = ["id", *ALERT_COLUMNS, "data"]
        params = [alert_id, *[values[c] for c in ALERT_COLUMNS], json.dumps(doc, ensure_ascii=False)]
        placeholders = ",".join("?" * len(columns))
        self._conn.execute(
            f"INSERT OR REPLACE INTO alerts ({','.join(columns)}) VALUES ({placeholders})",
            params,
        )
        self._conn.commit()
        return alert_id

    async def update_alert(self, alert_id: str, doc: dict[str, Any]) -> bool:
        """局部更新告警文档，文档不存在时返回 False。"""
        return await self._call(self._update_alert_sync, alert_id, doc)

    def _update_alert_sync(self, alert_id: str, doc: dict[str, Any]) -> bool:
        """同步合并更新告警字段并回写索引列。"""
        row = self._conn.execute("SELECT data FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            return False
        merged = json.loads(row["data"])
        merged.update(doc)
        values = _alert_row_values(merged)
        assignments = ",".join(f"{column} = ?" for column in ALERT_COLUMNS)
        params = [values[c] for c in ALERT_COLUMNS]
        self._conn.execute(
            f"UPDATE alerts SET {assignments}, data = ? WHERE id = ?",
            [*params, json.dumps(merged, ensure_ascii=False), alert_id],
        )
        self._conn.commit()
        return True

    async def increment_alert(
        self, alert_id: str, count: int, last_seen: datetime, sample: dict[str, Any] | None
    ) -> bool:
        """对已有告警累加计数、刷新时间并追加样本（用于告警聚合）。"""
        return await self._call(self._increment_alert_sync, alert_id, count, last_seen, sample)

    def _increment_alert_sync(
        self, alert_id: str, count: int, last_seen: datetime, sample: dict[str, Any] | None
    ) -> bool:
        """同步执行告警计数累加，样本最多保留 10 条。"""
        row = self._conn.execute("SELECT data FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            return False
        doc = json.loads(row["data"])
        doc["count"] = int(doc.get("count", 1)) + count
        stamp = last_seen.isoformat()
        doc["last_seen"] = stamp
        doc["updated_at"] = stamp
        if sample:
            samples = doc.get("samples") or []
            if len(samples) < 10:
                samples.append(sample)
            doc["samples"] = samples
        values = _alert_row_values(doc)
        assignments = ",".join(f"{column} = ?" for column in ALERT_COLUMNS)
        params = [values[c] for c in ALERT_COLUMNS]
        self._conn.execute(
            f"UPDATE alerts SET {assignments}, data = ? WHERE id = ?",
            [*params, json.dumps(doc, ensure_ascii=False), alert_id],
        )
        self._conn.commit()
        return True

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
        """通用检索，返回与 Elasticsearch 一致的响应结构。"""
        return await self._call(self._search_sync, index, query, sort, page, size, aggs)

    def _search_sync(
        self,
        index: str,
        query: dict[str, Any] | None,
        sort: list[Any] | None,
        page: int,
        size: int,
        aggs: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """同步执行检索：先算总数与聚合，再按分页取文档。"""
        table = self._table(index)
        where, params = _translate_query(query)
        total = int(
            self._conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0]
        )

        hits: list[dict[str, Any]] = []
        if size > 0:
            order = self._order_clause(table, sort)
            offset = max(0, (page - 1) * size)
            rows = self._conn.execute(
                f"SELECT * FROM {table} WHERE {where}{order} LIMIT ? OFFSET ?",
                [*params, size, offset],
            ).fetchall()
            hits = [self._to_hit(table, row) for row in rows]

        aggregations: dict[str, Any] = {}
        for name, spec in (aggs or {}).items():
            aggregations[name] = self._aggregate(table, where, params, spec)

        return {
            "hits": {"total": {"value": total}, "hits": hits},
            "aggregations": aggregations,
        }

    @staticmethod
    def _order_clause(table: str, sort: list[Any] | None) -> str:
        """把排序参数翻译成 ORDER BY 子句，默认按时间倒序。"""
        default_column = "last_seen_epoch" if table == "alerts" else "ts_epoch"
        if not sort:
            return f" ORDER BY {default_column} DESC"
        parts: list[str] = []
        for item in sort:
            field, options = next(iter(item.items()))
            column = (
                TIME_FIELDS[field][1] if field in TIME_FIELDS else _resolve_column(field)
            )
            if not column:
                continue
            direction = "ASC" if str(options.get("order", "desc")).lower() == "asc" else "DESC"
            parts.append(f"{column} {direction}")
        return f" ORDER BY {', '.join(parts)}" if parts else f" ORDER BY {default_column} DESC"

    @staticmethod
    def _to_hit(table: str, row: sqlite3.Row) -> dict[str, Any]:
        """把数据库行转换成 {_id, _source} 形式的检索结果。"""
        if table == "alerts":
            return {"_id": row["id"], "_source": json.loads(row["data"])}
        return {"_id": str(row["id"]), "_source": _row_to_log(row)}

    def _aggregate(
        self,
        table: str,
        where: str,
        params: list[Any],
        spec: dict[str, Any],
        extra_where: str = "",
        extra_params: tuple[Any, ...] = (),
    ) -> dict[str, Any]:
        """执行单个聚合（terms / date_histogram / sum / max）。"""
        condition = f"({where}){extra_where}"
        bound = [*params, *extra_params]

        if "terms" in spec:
            return self._terms_agg(table, condition, bound, spec)
        if "date_histogram" in spec:
            return self._histogram_agg(table, condition, bound, spec)
        if "sum" in spec:
            column = _resolve_column(spec["sum"].get("field", "")) or "count"
            value = self._conn.execute(
                f"SELECT SUM({column}) FROM {table} WHERE {condition}", bound
            ).fetchone()[0]
            return {"value": value or 0}
        if "max" in spec:
            field = spec["max"].get("field", "")
            if field in TIME_FIELDS:
                column = TIME_FIELDS[field][1]
                value = self._conn.execute(
                    f"SELECT MAX({column}) FROM {table} WHERE {condition}", bound
                ).fetchone()[0]
                if value is None:
                    return {"value": None}
                stamp = datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
                return {"value": value * 1000, "value_as_string": stamp}
            column = _resolve_column(field) or field
            value = self._conn.execute(
                f"SELECT MAX({column}) FROM {table} WHERE {condition}", bound
            ).fetchone()[0]
            return {"value": value}
        return {}

    def _terms_agg(
        self, table: str, condition: str, params: list[Any], spec: dict[str, Any]
    ) -> dict[str, Any]:
        """执行 terms 聚合，支持嵌套子聚合。"""
        cfg = spec["terms"]
        column = _resolve_column(cfg.get("field", ""))
        if not column:
            return {"buckets": []}
        limit = int(cfg.get("size", 10))
        rows = self._conn.execute(
            f"SELECT {column} AS k, COUNT(*) AS c FROM {table} "
            f"WHERE {condition} AND {column} IS NOT NULL "
            f"GROUP BY {column} ORDER BY c DESC LIMIT ?",
            [*params, limit],
        ).fetchall()
        sub_aggs = spec.get("aggs") or {}
        buckets = []
        for row in rows:
            bucket: dict[str, Any] = {"key": row["k"], "doc_count": int(row["c"])}
            for name, sub in sub_aggs.items():
                bucket[name] = self._aggregate(
                    table, condition, params, sub, f" AND {column} = ?", (row["k"],)
                )
            buckets.append(bucket)
        return {"buckets": buckets}

    def _histogram_agg(
        self, table: str, condition: str, params: list[Any], spec: dict[str, Any]
    ) -> dict[str, Any]:
        """执行 date_histogram 聚合，按 extended_bounds 与 min_doc_count 补齐空桶。"""
        cfg = spec["date_histogram"]
        field = cfg.get("field", "@timestamp")
        if field not in TIME_FIELDS:
            return {"buckets": []}
        column = TIME_FIELDS[field][1]
        step = _parse_interval(cfg.get("fixed_interval", "1h"))
        rows = self._conn.execute(
            f"SELECT ({column} / ?) * ? AS b, COUNT(*) AS c FROM {table} "
            f"WHERE {condition} GROUP BY b ORDER BY b",
            [step, step, *params],
        ).fetchall()
        counts = {int(row["b"]): int(row["c"]) for row in rows}

        bounds = cfg.get("extended_bounds") or {}
        if bounds.get("min") is not None and bounds.get("max") is not None:
            start = int(_to_epoch(bounds["min"]) // step * step)
            end = int(_to_epoch(bounds["max"]) // step * step)
        elif counts:
            start, end = min(counts), max(counts)
        else:
            start = end = 0

        sub_aggs = spec.get("aggs") or {}
        buckets = []
        current = start
        while current <= end:
            bucket: dict[str, Any] = {"key": current * 1000, "doc_count": counts.get(current, 0)}
            for name, sub in sub_aggs.items():
                bucket[name] = self._aggregate(
                    table, condition, params, sub,
                    f" AND {column} >= ? AND {column} < ?", (current, current + step),
                )
            buckets.append(bucket)
            current += step
        return {"buckets": buckets}

    async def count(self, index: str, query: dict[str, Any] | None = None) -> int:
        """统计满足条件的文档数。"""
        return await self._call(self._count_sync, index, query)

    def _count_sync(self, index: str, query: dict[str, Any] | None) -> int:
        """同步统计文档数。"""
        table = self._table(index)
        where, params = _translate_query(query)
        row = self._conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()
        return int(row[0])

    async def get_doc(self, index: str, doc_id: str) -> dict[str, Any] | None:
        """按 ID 获取文档，不存在返回 None。"""
        return await self._call(self._get_doc_sync, index, doc_id)

    def _get_doc_sync(self, index: str, doc_id: str) -> dict[str, Any] | None:
        """同步按 ID 查询文档。"""
        table = self._table(index)
        row = self._conn.execute(f"SELECT * FROM {table} WHERE id = ?", (doc_id,)).fetchone()
        if not row:
            return None
        payload = json.loads(row["data"]) if table == "alerts" else _row_to_log(row)
        return {"id": row["id"], **payload}

    async def update_by_query(
        self, index: str, query: dict[str, Any], script: dict[str, Any]
    ) -> int:
        """按条件批量更新（仅支持项目用到的 _id 列表 + 字段赋值形式）。"""
        return await self._call(self._update_by_query_sync, index, query, script)

    def _update_by_query_sync(
        self, index: str, query: dict[str, Any], script: dict[str, Any]
    ) -> int:
        """同步批量更新告警，返回受影响条数。"""
        ids = [str(item) for item in (query.get("terms") or {}).get("_id", [])]
        patch = script.get("params") or {}
        if not ids or not patch:
            return 0
        placeholders = ",".join("?" * len(ids))
        rows = self._conn.execute(
            f"SELECT id, data FROM alerts WHERE id IN ({placeholders})", ids
        ).fetchall()
        for row in rows:
            merged = json.loads(row["data"])
            merged.update(patch)
            values = _alert_row_values(merged)
            assignments = ",".join(f"{column} = ?" for column in ALERT_COLUMNS)
            self._conn.execute(
                f"UPDATE alerts SET {assignments}, data = ? WHERE id = ?",
                [*[values[c] for c in ALERT_COLUMNS], json.dumps(merged, ensure_ascii=False), row["id"]],
            )
        self._conn.commit()
        return len(rows)

    # ---------------- 维护 ----------------

    async def cleanup_old_indices(self) -> list[str]:
        """删除超过保留期的日志数据，返回被清理的按天索引名列表。"""
        return await self._call(self._cleanup_sync)

    def _cleanup_sync(self) -> list[str]:
        """同步删除过期日志行（保留告警，仅清理日志明细）。"""
        if self.retention_days <= 0:
            return []
        cutoff = int((datetime.now(timezone.utc) - timedelta(days=self.retention_days)).timestamp())
        rows = self._conn.execute(
            "SELECT DISTINCT date(ts) AS d FROM logs WHERE ts_epoch < ?", (cutoff,)
        ).fetchall()
        removed = [f"{self.prefix}-logs-{row['d'].replace('-', '.')}" for row in rows if row["d"]]
        cursor = self._conn.execute("DELETE FROM logs WHERE ts_epoch < ?", (cutoff,))
        self._conn.commit()
        if removed:
            logger.info("已清理过期日志 %s 条：%s", cursor.rowcount, ", ".join(removed))
        return removed

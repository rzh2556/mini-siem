"""数据模型定义：归一化日志事件、告警、规则以及 API 出入参。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["open", "acknowledged", "closed"]
SourceType = Literal["nginx", "apache", "ssh", "windows", "syslog", "linux", "unknown"]


def utcnow() -> datetime:
    """返回带时区的当前 UTC 时间。"""
    return datetime.now(timezone.utc)


class GeoInfo(BaseModel):
    """IP 地理位置信息，用于攻击地图展示。"""

    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None


class LogEvent(BaseModel):
    """归一化后的日志事件，所有采集源的日志都会被解析成该结构。"""

    id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    host: str = "unknown"
    source_type: SourceType = "unknown"
    level: str = "info"

    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None

    user: str | None = None
    method: str | None = None
    url: str | None = None
    path: str | None = None
    query: str | None = None
    status_code: int | None = None
    user_agent: str | None = None

    event_id: int | None = None
    channel: str | None = None
    process: str | None = None
    command: str | None = None

    message: str = ""
    raw: str = ""
    tags: list[str] = Field(default_factory=list)
    geo: GeoInfo | None = None
    matched_rules: list[str] = Field(default_factory=list)

    def es_doc(self) -> dict[str, Any]:
        """转换成写入 Elasticsearch 的文档结构（时间字段用 @timestamp）。"""
        doc = self.model_dump(exclude_none=True)
        doc.pop("id", None)
        doc["@timestamp"] = doc.pop("timestamp")
        return doc


class AlertSample(BaseModel):
    """告警关联的原始日志样本（最多保留若干条）。"""

    timestamp: datetime
    host: str | None = None
    src_ip: str | None = None
    raw: str = ""


class Alert(BaseModel):
    """检测规则命中后生成的告警（同规则同分组会在冷却窗口内聚合成一条）。"""

    id: str | None = None
    rule_id: str
    rule_name: str
    severity: Severity = "medium"
    status: AlertStatus = "open"

    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    count: int = 1
    group_key: str = ""

    src_ip: str | None = None
    dst_ip: str | None = None
    host: str | None = None
    user: str | None = None

    description: str = ""
    tags: list[str] = Field(default_factory=list)
    samples: list[AlertSample] = Field(default_factory=list)
    geo: GeoInfo | None = None
    ack_comment: str | None = None

    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class RuleCondition(BaseModel):
    """单条匹配条件：针对某个归一化字段做正则/等值/包含判断。"""

    field: str = "raw"
    regex: str | None = None
    equals: Any | None = None
    contains: str | None = None
    in_: list[Any] | None = Field(default=None, alias="in")
    not_in: list[Any] | None = None
    gt: float | None = None
    lt: float | None = None

    model_config = {"populate_by_name": True}


class ThresholdConfig(BaseModel):
    """阈值/频率类规则配置：窗口内同分组命中次数达到 count 即告警。"""

    count: int = 5
    window: int = 300
    group_by: list[str] = Field(default_factory=lambda: ["src_ip"])


class TimeWindowConfig(BaseModel):
    """时间窗条件：用于识别非工作时间登录等场景。"""

    start: str = "08:00"
    end: str = "20:00"
    mode: Literal["inside", "outside"] = "outside"


class SuppressionConfig(BaseModel):
    """降噪配置：冷却窗口、IP 白名单等。"""

    cooldown: int | None = None
    ignore_ips: list[str] = Field(default_factory=list)
    ignore_internal: bool = False


class Rule(BaseModel):
    """检测规则定义，对应 rules/ 目录下的 YAML 文件。"""

    id: str
    name: str
    description: str = ""
    severity: Severity = "medium"
    type: Literal["match", "threshold", "first_seen"] = "match"
    enabled: bool = True
    log_types: list[str] = Field(default_factory=lambda: ["any"])
    tags: list[str] = Field(default_factory=list)

    all_of: list[RuleCondition] = Field(default_factory=list)
    any_of: list[RuleCondition] = Field(default_factory=list)
    time_window: TimeWindowConfig | None = None

    threshold: ThresholdConfig | None = None
    first_seen_field: str = "src_ip"
    first_seen_lookback: int = 30 * 24 * 3600
    suppression: SuppressionConfig = Field(default_factory=SuppressionConfig)

    # 运行期统计字段
    enabled_source: str = "file"


# ---------------- API 出入参 ----------------


class IngestEvent(BaseModel):
    """Agent 上报的单条事件，fields 为结构化字段（如 Windows 事件日志）。"""

    raw: str = ""
    timestamp: datetime | None = None
    fields: dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    """Agent 批量上报请求体。"""

    host: str = "unknown"
    source_type: SourceType = "unknown"
    events: list[IngestEvent] = Field(default_factory=list)


class IngestResponse(BaseModel):
    """上报结果。"""

    accepted: int
    alerts: int


class RuleUpdate(BaseModel):
    """规则在线调整入参。"""

    enabled: bool | None = None
    severity: Severity | None = None
    threshold: ThresholdConfig | None = None


class AlertUpdate(BaseModel):
    """告警状态更新入参。"""

    status: AlertStatus | None = None
    comment: str | None = None


class BulkAlertUpdate(BaseModel):
    """告警批量更新入参。"""

    ids: list[str]
    status: AlertStatus


class SearchResult(BaseModel):
    """通用分页查询结果。"""

    total: int
    items: list[dict[str, Any]]


class UploadPreviewItem(BaseModel):
    """上传文件解析结果的单条预览。"""

    timestamp: datetime
    src_ip: str | None = None
    user: str | None = None
    level: str = "info"
    message: str = ""
    matched: list[str] = Field(default_factory=list)


class UploadResult(BaseModel):
    """日志文件上传解析结果。"""

    filename: str
    source_type: str
    auto_detected: bool
    total_lines: int
    accepted: int
    skipped: int
    alerts: int
    preview: list[UploadPreviewItem] = Field(default_factory=list)

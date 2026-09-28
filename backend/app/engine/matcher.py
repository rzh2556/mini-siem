"""规则匹配引擎：对归一化日志执行条件匹配，产出规则命中结果。"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from app.models.schemas import LogEvent, Rule, RuleCondition

logger = logging.getLogger(__name__)


def _resolve_local_tz(tz_name: str = "Asia/Shanghai"):
    """获取本地时区对象，系统缺少时区数据库时退化为固定 UTC+8。"""
    try:
        return ZoneInfo(tz_name)
    except Exception:  # noqa: BLE001 - 精简镜像/Windows 可能缺少 tzdata
        return timezone(timedelta(hours=8))


LOCAL_TZ = _resolve_local_tz()


@dataclass
class RuleHit:
    """一次规则命中结果。"""

    rule: Rule
    event: LogEvent
    groups: dict[str, str] = field(default_factory=dict)  # 分组键值，如 {"src_ip": "1.2.3.4"}
    extracted: dict[str, str] = field(default_factory=dict)  # 正则命名分组提取的字段


class RuleEngine:
    """规则集合管理器，负责编译正则并执行匹配。"""

    def __init__(self) -> None:
        """初始化内部规则缓存。"""
        self._rules: list[Rule] = []
        self._regex_cache: dict[int, re.Pattern[str]] = {}

    def set_rules(self, rules: list[Rule]) -> None:
        """更新规则集合并预编译正则表达式。"""
        self._rules = [r for r in rules if r.enabled]
        self._regex_cache.clear()
        for idx, rule in enumerate(self._rules):
            for cond_idx, cond in enumerate(list(rule.all_of) + list(rule.any_of)):
                if cond.regex:
                    self._regex_cache[(idx, cond_idx)] = self._compile(cond.regex, rule.id)
        logger.info("规则引擎就绪，启用规则 %s 条", len(self._rules))

    @staticmethod
    def _compile(pattern: str, rule_id: str) -> re.Pattern[str] | None:
        """编译正则表达式，编译失败返回 None。"""
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            logger.error("规则 %s 正则非法: %s", rule_id, exc)
            return None

    @property
    def rules(self) -> list[Rule]:
        """返回当前启用中的规则列表。"""
        return list(self._rules)

    def evaluate(self, event: LogEvent) -> list[RuleHit]:
        """对单条日志执行全部规则匹配，返回命中列表。"""
        hits: list[RuleHit] = []
        for idx, rule in enumerate(self._rules):
            if not self._log_type_match(rule, event):
                continue
            if rule.type == "first_seen":
                hit = self._match_rule(idx, rule, event)
                if hit:
                    hits.append(hit)
                continue
            hit = self._match_rule(idx, rule, event)
            if hit:
                hits.append(hit)
        return hits

    @staticmethod
    def _log_type_match(rule: Rule, event: LogEvent) -> bool:
        """校验日志类型是否符合规则声明的范围。"""
        if not rule.log_types or "any" in rule.log_types:
            return True
        return event.source_type in rule.log_types

    def _match_rule(self, idx: int, rule: Rule, event: LogEvent) -> RuleHit | None:
        """按 all_of / any_of / time_window 判断规则是否命中。"""
        if rule.time_window and not self._in_time_window(rule, event):
            return None

        extracted: dict[str, str] = {}
        if rule.all_of:
            for cond_idx, cond in enumerate(rule.all_of):
                if not self._match_condition(self._regex_cache.get((idx, cond_idx)), cond, event, extracted):
                    return None
        if rule.any_of:
            matched_any = False
            for offset, cond in enumerate(rule.any_of):
                cond_idx = len(rule.all_of) + offset
                if self._match_condition(self._regex_cache.get((idx, cond_idx)), cond, event, extracted):
                    matched_any = True
                    break
            if not matched_any:
                return None
        if not rule.all_of and not rule.any_of:
            return None

        groups = {key: str(value) for key, value in extracted.items() if value}
        return RuleHit(rule=rule, event=event, groups=groups, extracted=extracted)

    def _match_condition(
        self,
        regex: re.Pattern[str] | None,
        cond: RuleCondition,
        event: LogEvent,
        extracted: dict[str, str],
    ) -> bool:
        """执行单个条件判断：支持 regex / equals / contains / in / gt / lt。"""
        value = get_field_value(event, cond.field, extracted)

        if cond.regex:
            if regex is None or value is None:
                return False
            match = regex.search(str(value))
            if not match:
                return False
            if match.groupdict():
                extracted.update({k: v for k, v in match.groupdict().items() if v})
        if cond.equals is not None and str(value) != str(cond.equals):
            return False
        if cond.contains and (value is None or str(cond.contains).lower() not in str(value).lower()):
            return False
        if cond.in_ is not None and str(value) not in [str(v) for v in cond.in_]:
            return False
        if cond.not_in is not None and str(value) in [str(v) for v in cond.not_in]:
            return False
        if cond.gt is not None and not _compare(value, cond.gt, "gt"):
            return False
        if cond.lt is not None and not _compare(value, cond.lt, "lt"):
            return False
        return True

    @staticmethod
    def _in_time_window(rule: Rule, event: LogEvent) -> bool:
        """判断事件时间是否落在规则声明的时间窗内/外。"""
        window = rule.time_window
        if window is None:
            return True
        local_dt = event.timestamp.astimezone(LOCAL_TZ)
        start = time.fromisoformat(window.start)
        end = time.fromisoformat(window.end)
        current = local_dt.time()
        inside = start <= current <= end if start <= end else (current >= start or current <= end)
        return inside if window.mode == "inside" else not inside


def get_field_value(event: LogEvent, field_name: str, extracted: dict[str, str] | None = None) -> Any:
    """从事件或已提取字段中取值，支持 detail.xxx 形式的嵌套取值。"""
    if extracted and field_name in extracted:
        return extracted[field_name]
    value: Any = event
    for part in field_name.split("."):
        value = getattr(value, part, None) if not isinstance(value, dict) else value.get(part)
        if value is None:
            return None
    if field_name == "url" and not value:
        return event.url or event.path
    return value


def _compare(value: Any, threshold: float, op: str) -> bool:
    """数值比较辅助函数。"""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return False
    return num > threshold if op == "gt" else num < threshold


def format_description(rule: Rule, hit: RuleHit) -> str:
    """用命中事件的字段渲染规则描述模板。"""
    values = {**hit.extracted, **hit.groups}
    values.update(
        {
            "src_ip": hit.event.src_ip or "-",
            "user": hit.event.user or "-",
            "host": hit.event.host or "-",
            "url": hit.event.url or "-",
            "event_id": hit.event.event_id or "-",
            "count": rule.threshold.count if rule.threshold else 1,
        }
    )
    template = rule.description or rule.name
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return template


def local_day_range(days: int = 1) -> tuple[datetime, datetime]:
    """返回本地时区下最近 N 天的起止时间（UTC）。"""
    now = datetime.now(LOCAL_TZ)
    start = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    return start.astimezone(timezone.utc), now.astimezone(timezone.utc)

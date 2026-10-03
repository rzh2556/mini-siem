"""Windows EVTX 事件日志文件解析（跨平台，纯 Python）。

服务端通常运行在 Linux 上，无法像 Windows Agent 那样调用 win32evtlog，
因此这里使用 python-evtx 库直接解析 .evtx 二进制文件，再按与 Agent
完全一致的字段口径（见 agent/siem_agent.py 的 parse_windows_xml）
提取结构化字段，复用 parse_windows 归一化逻辑。
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from app.normalize.parsers import parse_ts

logger = logging.getLogger(__name__)

# Windows 事件 XML 的命名空间
EVT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# EventData 字段名 -> 归一化字段，与采集 Agent 保持一致
FIELD_ALIASES: dict[str, list[str]] = {
    "user": ["TargetUserName", "SubjectUserName", "NewTargetUserName", "MemberName", "param1"],
    "src_ip": ["IpAddress", "ClientAddress", "SourceNetworkAddress"],
    "process": ["NewProcessName", "ImagePath", "ProcessName", "ServiceFileName"],
    "command": ["ProcessCommandLine", "CommandLine", "ServiceStartName"],
}

# EVTX 文件魔数：ElfFile\\x00
EVTX_MAGIC = b"ElfFile\x00"

# 秒以下的时间片段可能是 7 位（Windows 偶发），统一截成 6 位微秒，兼容旧版 Python
_FRACTION_RE = re.compile(r"(\.\d{1,7})(?=Z|[+-]\d{2}:?\d{2}$)")


def is_evtx_content(raw: bytes) -> bool:
    """根据文件头魔数判断是否为 EVTX 二进制文件。"""
    return raw[:8] == EVTX_MAGIC


def _parse_system_time(value: str | None) -> datetime | None:
    """解析 Windows 事件的 SystemTime（如 2024-05-01T12:00:00.123456Z）。"""
    if not value:
        return None
    normalized = _FRACTION_RE.sub(lambda m: (m.group(1)[:7]).ljust(7, "0"), value)
    # 上面把小数秒补齐到 6 位（含小数点共 7 个字符）
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return parse_ts(value)
    # Windows 事件时间统一按 UTC 处理：部分 EVTX 的 SystemTime 不带时区，
    # 若返回 naive 时间会与其它日志源（parse_ts 统一返回 aware UTC）混用而报错
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_record_xml(xml_str: str) -> dict[str, Any] | None:
    """解析单条事件 XML，返回 {raw, fields, timestamp}；结构非法时返回 None。"""
    root = ET.fromstring(xml_str)
    system = root.find("e:System", EVT_NS)
    if system is None:
        return None

    event_id = int(system.findtext("e:EventID", "0", EVT_NS) or 0)
    level_text = system.findtext("e:Level", "", EVT_NS) or ""
    channel = system.findtext("e:Channel", "", EVT_NS) or "Windows"
    computer = system.findtext("e:Computer", "", EVT_NS)
    provider = system.find("e:Provider", EVT_NS)
    created = system.find("e:TimeCreated", EVT_NS)

    # EventData 是标准承载区；部分老事件把数据放在 UserData，做兜底提取
    data: dict[str, str] = {}
    for item in root.findall(".//e:EventData/e:Data", EVT_NS):
        name = item.get("Name")
        if name:
            data[name] = (item.text or "").strip()
    if not data:
        for item in root.findall(".//e:UserData//*", EVT_NS):
            tag = item.tag.rsplit("}", 1)[-1]
            if item.text and item.text.strip() and tag not in data:
                data[tag] = item.text.strip()

    timestamp = _parse_system_time(created.get("SystemTime") if created is not None else None)

    fields: dict[str, Any] = {
        "event_id": event_id,
        "channel": channel,
        "host": computer or None,
        "level": int(level_text) if level_text.isdigit() else (level_text or None),
        "provider": provider.get("Name") if provider is not None else None,
        "timestamp": created.get("SystemTime") if created is not None else None,
    }
    for target, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if data.get(alias):
                fields[target] = data[alias]
                break

    detail = "; ".join(f"{key}: {value}" for key, value in data.items() if value)
    message = f"[{channel}] EventID={event_id} {detail}".strip()[:4000]
    fields["message"] = message

    return {"raw": message, "fields": fields, "timestamp": timestamp}


def parse_evtx(raw: bytes, max_records: int) -> tuple[list[dict[str, Any]], int]:
    """解析 EVTX 文件内容。

    返回 (事件列表, 跳过条数)。每条事件为 {raw, fields, timestamp}，
    可直接组装成 IngestEvent。损坏的单条记录计入跳过数，不影响其他记录。
    """
    # 延迟导入：未使用 EVTX 上传时无需加载该依赖
    from Evtx.Evtx import Evtx

    events: list[dict[str, Any]] = []
    skipped = 0
    truncated = 0
    # python-evtx 的 Evtx 只接受磁盘路径（内部 open + mmap），
    # 因此先把上传的二进制内容写入临时文件，解析结束后删除
    fd, tmp_path = tempfile.mkstemp(suffix=".evtx", prefix="siem_evtx_")
    try:
        with os.fdopen(fd, "wb") as tmp_file:
            tmp_file.write(raw)
        with Evtx(tmp_path) as log:
            for index, record in enumerate(log.records()):
                if index >= max_records:
                    truncated += 1
                    continue
                try:
                    xml_str = record.xml()
                    parsed = _parse_record_xml(xml_str)
                except Exception as exc:  # 单条损坏不应导致整个文件失败
                    logger.debug("EVTX 第 %s 条记录解析失败，已跳过: %s", index + 1, exc)
                    parsed = None
                if parsed is None:
                    skipped += 1
                else:
                    events.append(parsed)
    finally:
        os.unlink(tmp_path)
    return events, skipped + truncated

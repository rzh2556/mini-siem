#!/usr/bin/env python3
"""Mini SIEM 采集 Agent：采集 Linux 日志文件与 Windows 事件日志并上报到服务端。

特点：
1. 仅依赖 Python 3.9+ 标准库（Windows 事件日志采集需要 pywin32）；
2. 通过状态文件记录读取偏移量，重启后不重复采集、不丢日志；
3. 支持日志轮转（文件被截断或 inode 变化时自动从头读取）。

用法：
    python siem_agent.py --config config.yml
    python siem_agent.py --config config.yml --once      # 只采集一次，便于验证
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

try:  # YAML 为可选依赖，缺失时使用 JSON 配置
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

DEFAULT_STATE_DIR = Path(__file__).resolve().parent / "state"


# ---------------------------------------------------------------- 配置


def load_config(path: str) -> dict:
    """加载 Agent 配置文件（YAML 或 JSON）。"""
    text = Path(path).read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(text)
    return json.loads(text)


class AgentState:
    """采集进度状态：记录每个日志源的读取位置与 Windows 事件记录号。"""

    def __init__(self, state_dir: Path) -> None:
        """加载本地状态文件。"""
        self.path = state_dir / "agent_state.json"
        self.data: dict = {}
        if self.path.exists():
            self.data = json.loads(self.path.read_text(encoding="utf-8"))

    def get(self, key: str) -> dict:
        """读取某个日志源的状态。"""
        return self.data.get(key, {})

    def set(self, key: str, value: dict) -> None:
        """更新某个日志源的状态并落盘。"""
        self.data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- 上报


class Reporter:
    """负责把采集到的事件批量推送到 Mini SIEM 服务端。"""

    def __init__(self, url: str, token: str, host: str, batch_size: int = 500) -> None:
        """初始化上报地址与鉴权信息。"""
        self.endpoint = url.rstrip("/") + "/api/v1/ingest"
        self.token = token
        self.host = host
        self.batch_size = batch_size

    def send(self, source_type: str, events: list[dict]) -> int:
        """批量上报事件，返回成功上报的条数（失败时返回 0 并记录日志）。"""
        if not events:
            return 0
        payload = json.dumps(
            {"host": self.host, "source_type": source_type, "events": events},
            ensure_ascii=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json", "X-Agent-Token": self.token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return int(body.get("accepted", 0))
        except urllib.error.HTTPError as exc:
            print(f"[ERROR] 上报失败 HTTP {exc.code}: {exc.read()[:200]!r}", file=sys.stderr)
        except urllib.error.URLError as exc:
            print(f"[ERROR] 无法连接服务端 {self.endpoint}: {exc.reason}", file=sys.stderr)
        return 0


# ---------------------------------------------------------------- 文件采集


def read_new_lines(state: AgentState, source: dict) -> list[str]:
    """增量读取文本日志文件的新增行（支持日志轮转）。"""
    path = Path(source["path"])
    if not path.exists():
        return []
    key = source["name"]
    stat = path.stat()
    prev = state.get(key)
    offset = prev.get("offset", 0)
    inode = prev.get("inode")

    # 文件被轮转或截断时从头读取
    current_inode = getattr(stat, "st_ino", None)
    if inode is not None and current_inode is not None and inode != current_inode:
        offset = 0
    if stat.st_size < offset:
        offset = 0

    with path.open("r", encoding=source.get("encoding", "utf-8"), errors="ignore") as fh:
        fh.seek(offset)
        lines = [line.rstrip("\n") for line in fh if line.strip()]
        new_offset = fh.tell()

    state.set(key, {"path": str(path), "offset": new_offset, "inode": current_inode})
    return lines


# ---------------------------------------------------------------- Windows 事件日志

# Windows 事件 XML 命名空间
EVT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# 事件数据字段 -> 归一化字段的映射
FIELD_ALIASES = {
    "user": ["TargetUserName", "SubjectUserName", "NewTargetUserName", "MemberName", "param1"],
    "src_ip": ["IpAddress", "ClientAddress", "SourceNetworkAddress"],
    "process": ["NewProcessName", "ImagePath", "ProcessName", "ServiceFileName"],
    "command": ["ProcessCommandLine", "CommandLine", "ServiceStartName"],
}


def read_windows_events(state: AgentState, source: dict) -> list[dict]:
    """读取 Windows 事件日志（Security/System 等频道）中新增的事件。"""
    try:
        import win32evtlog  # type: ignore
    except ImportError:
        print("[WARN] 未安装 pywin32，跳过 Windows 事件日志采集（pip install pywin32）", file=sys.stderr)
        return []

    channel = source.get("windows_event_log", "Security")
    event_ids = source.get("event_ids") or []
    key = source["name"]
    last_record = state.get(key).get("last_record_id", 0)

    xpath = "*"
    if event_ids:
        xpath = "*[System[(" + " or ".join(f"EventID={eid}" for eid in event_ids) + ")]]"

    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    handle = win32evtlog.EvtQuery(channel, flags, xpath)
    events: list[dict] = []
    max_record = last_record

    while True:
        batch = win32evtlog.EvtNext(handle, 64)
        if not batch:
            break
        stop = False
        for evt in batch:
            xml_str = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
            parsed, record_id = parse_windows_xml(xml_str, channel)
            if record_id and record_id <= last_record:
                stop = True  # 逆序查询，遇到已处理记录即可停止
                break
            if record_id:
                max_record = max(max_record, record_id)
            if parsed:
                events.append(parsed)
        if stop:
            break

    if max_record > last_record:
        state.set(key, {"last_record_id": max_record})
    return list(reversed(events))


def parse_windows_xml(xml_str: str, channel: str) -> tuple[dict | None, int]:
    """解析 Windows 事件 XML，返回 (归一化事件字段, 记录号)。"""
    root = ET.fromstring(xml_str)
    system = root.find("e:System", EVT_NS)
    if system is None:
        return None, 0

    event_id = int(system.findtext("e:EventID", "0", EVT_NS) or 0)
    record_id = int(system.findtext("e:EventRecordID", "0", EVT_NS) or 0)
    level = system.findtext("e:Level", "", EVT_NS)
    provider = system.find("e:Provider", EVT_NS)
    created = system.find("e:TimeCreated", EVT_NS)

    data: dict[str, str] = {}
    for item in root.findall(".//e:EventData/e:Data", EVT_NS):
        name = item.get("Name")
        if name:
            data[name] = (item.text or "").strip()

    fields: dict = {
        "event_id": event_id,
        "channel": channel,
        "level": int(level) if level.isdigit() else level,
        "provider": provider.get("Name") if provider is not None else None,
        "timestamp": created.get("SystemTime") if created is not None else None,
    }
    for target, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if data.get(alias):
                fields[target] = data[alias]
                break

    # 组装可读消息，便于规则按文本匹配（如 LogonType 判断 RDP）
    detail = "; ".join(f"{k}: {v}" for k, v in data.items() if v)
    fields["message"] = f"[{channel}] EventID={event_id} {detail}"[:4000]
    return fields, record_id


# ---------------------------------------------------------------- 主循环


def collect_once(config: dict, state: AgentState, reporter: Reporter) -> int:
    """执行一轮采集并上报，返回本轮上报的事件总数。"""
    total = 0
    for source in config.get("sources", []):
        if not source.get("enabled", True):
            continue
        source_type = source.get("source_type", "syslog")
        if source.get("windows_event_log"):
            events = read_windows_events(state, source)
            payload = [{"raw": e["message"], "timestamp": e.get("timestamp"), "fields": e} for e in events]
        else:
            lines = read_new_lines(state, source)
            payload = [{"raw": line} for line in lines]

        if not payload:
            continue
        batch_size = reporter.batch_size
        for index in range(0, len(payload), batch_size):
            chunk = payload[index : index + batch_size]
            sent = reporter.send(source_type, chunk)
            total += sent
            if sent == 0 and chunk:
                print(f"[WARN] {source['name']} 有 {len(chunk)} 条日志上报失败，将在下轮重试", file=sys.stderr)
    return total


def build_reporter(config: dict) -> Reporter:
    """根据配置构造上报器。"""
    server = config.get("server", {})
    host = server.get("host") or socket.gethostname()
    return Reporter(
        url=server.get("url", "http://127.0.0.1:8000"),
        token=server.get("token", ""),
        host=host,
        batch_size=int(server.get("batch_size", 500)),
    )


def main() -> int:
    """命令行入口：解析参数并启动采集循环。"""
    parser = argparse.ArgumentParser(description="Mini SIEM 日志采集 Agent")
    parser.add_argument("--config", default="config.yml", help="配置文件路径")
    parser.add_argument("--once", action="store_true", help="仅采集一轮后退出")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="状态文件目录")
    args = parser.parse_args()

    config = load_config(args.config)
    state = AgentState(Path(args.state_dir))
    reporter = build_reporter(config)
    interval = int(config.get("server", {}).get("interval", 5))

    print(f"[INFO] Agent 启动: 上报地址={reporter.endpoint} 主机={reporter.host} 间隔={interval}s")
    while True:
        try:
            count = collect_once(config, state, reporter)
            if count:
                print(f"[INFO] {datetime.now(timezone.utc).isoformat()} 已上报 {count} 条日志")
        except KeyboardInterrupt:
            print("[INFO] 收到退出信号，Agent 停止")
            return 0
        except Exception as exc:  # 采集异常不退出，下一轮自动重试
            print(f"[ERROR] 采集轮次异常: {exc}", file=sys.stderr)
        if args.once:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())

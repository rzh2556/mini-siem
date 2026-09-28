"""日志归一化解析器：把 Nginx/Apache/SSH/Windows/Syslog 等原始日志解析为统一的 LogEvent。

设计要点：
1. 所有解析函数只负责“原始文本 -> 字段字典”，字段组装统一由 build_event 完成；
2. 解析失败不抛异常，而是退化为只保留 raw/message 的通用事件，保证日志不丢；
3. url 字段保留原始请求串，query 字段保存 URL 解码后的请求串，便于规则检测编码后的攻击载荷。
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit

from app.models.schemas import LogEvent
from app.utils.net import extract_ips, is_valid_ip

# ---------------- 正则定义 ----------------

# Nginx/Apache 通用访问日志: combined 格式
ACCESS_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Za-z]+) (?P<request>[^"]*?)(?: (?P<proto>HTTP/[\d.]+))?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

# 简化格式（无 referer/ua）
ACCESS_SIMPLE_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Za-z]+) (?P<request>[^"]*?)" (?P<status>\d{3}) (?P<size>\S+)'
)

# Nginx error log
NGINX_ERROR_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#\d+: "
    r"(?:\*\d+ )?(?P<message>.*?)(?:, client: (?P<src_ip>[^,]+))?(?:, server: (?P<server>[^,]+))?"
    r"(?:, request: \"(?P<request>[^\"]*)\")?.*$"
)

# Apache error log
APACHE_ERROR_RE = re.compile(
    r"^\[(?P<ts>\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] "
    r"\[(?P<module>[\w:]+)\] \[pid (?P<pid>\d+)\](?: \[client (?P<src_ip>[^\]:]+)(?::\d+)?\])? (?P<message>.*)$"
)

# SSH 认证相关
SSH_FAILED_RE = re.compile(
    r"Failed (?P<method>password|publickey|none) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/\S+) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)
SSH_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)?")
SSH_PAM_FAIL_RE = re.compile(
    r"authentication failure;.*?(?:rhost=(?P<src_ip>\S+))?.*?user=(?P<user>\S+)"
)
SSH_DISCONNECT_RE = re.compile(
    r"(?:Disconnected from|Connection closed by|Received disconnect from) (?:authenticating user (?P<user>\S+) )?(?P<src_ip>\S+) port (?P<port>\d+)"
)
SUDO_RE = re.compile(
    r"^(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<command>.+)$"
)

# Syslog RFC3164 / RFC5424
SYSLOG_RFC3164_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<process>[\w\-/\.]+)(?:\[(?P<pid>\d+)\])?: ?(?P<message>.*)$"
)
SYSLOG_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<ver>\d) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) ?(?:- |(?P<structured>\[.*?\]))?(?P<message>.*)$"
)

LEVEL_NUM_MAP = {
    "0": "critical", "1": "critical", "2": "error", "3": "warning",
    "4": "info", "5": "info", "6": "info", "7": "info",
}

WINDOWS_LEVEL_MAP = {
    1: "critical", 2: "error", 3: "warning", 4: "info", 5: "info",
    "critical": "critical", "error": "error", "warning": "warning", "information": "info",
    "info": "info", "verbose": "info",
}

NGINX_LEVEL_MAP = {
    "emerg": "critical", "alert": "critical", "crit": "critical",
    "error": "error", "warn": "warning", "notice": "info", "info": "info", "debug": "info",
}


def parse_ts(value: str) -> datetime:
    """解析多种日志时间格式，失败时回退为当前 UTC 时间。"""
    value = (value or "").strip()
    formats = (
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y/%m/%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%a %b %d %H:%M:%S %Y",
        "%a %b %d %H:%M:%S.%f %Y",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    )
    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            if "%Y" not in fmt:
                dt = dt.replace(year=datetime.now().year)
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def safe_int(value: Any) -> int | None:
    """把任意值安全转换成 int，失败返回 None。"""
    if value is None or value == "-":
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def normalize_level(value: Any) -> str:
    """把各种来源的等级表示统一成 critical/error/warning/info。

    兼容 Windows 事件 Level(1-5)、syslog 数字等级(0-7)、文本等级字符串。
    """
    if isinstance(value, str) and not value.strip().isdigit():
        mapped = WINDOWS_LEVEL_MAP.get(value.strip().lower())
        return mapped or value.strip().lower() or "info"
    number = safe_int(value)
    if number is None:
        return "info"
    if 1 <= number <= 5:
        return WINDOWS_LEVEL_MAP.get(number, "info")
    return LEVEL_NUM_MAP.get(str(number), "info")


def split_request(request: str) -> dict[str, str | None]:
    """拆分请求串为 path(带查询串) 与 path_only 两部分。"""
    if not request:
        return {"url": None, "path": None}
    parts = urlsplit(request if request.startswith("/") or "://" in request else "/" + request)
    full = parts.path + ("?" + parts.query if parts.query else "")
    return {"url": full, "path": parts.path or None}


def parse_access_log(line: str) -> dict[str, Any]:
    """解析 Nginx/Apache 访问日志（combined 或 simplified 格式）。"""
    match = ACCESS_RE.match(line) or ACCESS_SIMPLE_RE.match(line)
    if not match:
        return {}
    data = match.groupdict()
    req = split_request(data.get("request") or "")
    status = safe_int(data.get("status"))
    level = "info"
    if status and status >= 500:
        level = "error"
    elif status and status >= 400:
        level = "warning"
    fields: dict[str, Any] = {
        "timestamp": parse_ts(data.get("ts", "")),
        "src_ip": data.get("src_ip"),
        "user": None if data.get("user") in (None, "-") else data["user"],
        "method": (data.get("method") or "").upper() or None,
        "url": req["url"],
        "path": req["path"],
        "query": unquote(req["url"] or "") or None,
        "status_code": status,
        "user_agent": data.get("ua") or None,
        "level": level,
        "message": line.strip(),
    }
    if not is_valid_ip(fields["src_ip"]):
        fields["src_ip"] = None
    return fields


def parse_nginx_error(line: str) -> dict[str, Any]:
    """解析 Nginx error.log。"""
    match = NGINX_ERROR_RE.match(line)
    if not match:
        return {}
    data = match.groupdict()
    req = split_request(data.get("request") or "")
    return {
        "timestamp": parse_ts(data.get("ts", "")),
        "src_ip": data.get("src_ip") if is_valid_ip(data.get("src_ip")) else None,
        "level": NGINX_LEVEL_MAP.get((data.get("level") or "").lower(), "warning"),
        "method": (req["url"] or "").split(" ")[0].strip() if req["url"] else None,
        "url": req["url"],
        "path": req["path"],
        "query": unquote(req["url"] or "") or None,
        "process": "nginx",
        "message": data.get("message", line.strip()),
    }


def parse_apache_error(line: str) -> dict[str, Any]:
    """解析 Apache error.log。"""
    match = APACHE_ERROR_RE.match(line)
    if not match:
        return {}
    data = match.groupdict()
    src_ip = data.get("src_ip")
    if src_ip and not is_valid_ip(src_ip):
        ips = extract_ips(data.get("message", ""))
        src_ip = ips[0] if ips else None
    return {
        "timestamp": parse_ts(data.get("ts", "")),
        "src_ip": src_ip if is_valid_ip(src_ip) else None,
        "level": "error" if "error" in (data.get("module") or "") else "warning",
        "process": "apache",
        "message": data.get("message", line.strip()),
    }


def parse_ssh(line: str) -> dict[str, Any]:
    """解析 Linux 认证日志（/var/log/secure、auth.log 中的 sshd/sudo/systemd-logind）。"""
    ts_match = re.match(r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w\-/\.]+)(?:\[(?P<pid>\d+)\])?: ?(?P<body>.*)$", line)
    ts = parse_ts(ts_match.group("ts")) if ts_match else datetime.now(timezone.utc)
    body = ts_match.group("body") if ts_match else line
    process = ts_match.group("proc") if ts_match else "sshd"

    result: dict[str, Any] = {
        "timestamp": ts,
        "process": process,
        "message": body,
        "level": "info",
    }

    if match := SSH_FAILED_RE.search(body):
        result.update(
            src_ip=match.group("src_ip"),
            user=match.group("user"),
            src_port=safe_int(match.group("port")),
            level="warning",
            tags=["auth.failed"],
        )
    elif match := SSH_ACCEPTED_RE.search(body):
        result.update(
            src_ip=match.group("src_ip"),
            user=match.group("user"),
            src_port=safe_int(match.group("port")),
            tags=["auth.success"],
        )
    elif match := SSH_INVALID_USER_RE.search(body):
        result.update(
            src_ip=match.group("src_ip"),
            user=match.group("user"),
            src_port=safe_int(match.group("port")),
            level="warning",
            tags=["auth.invalid_user"],
        )
    elif SUDO_RE.search(body):
        match = SUDO_RE.search(body)
        result.update(
            user=match.group("user"),
            command=match.group("command"),
            tags=["sudo"],
            level="warning" if "authentication failure" in body.lower() else "info",
        )
    elif match := SSH_PAM_FAIL_RE.search(body):
        if match.groupdict().get("src_ip"):
            result["src_ip"] = match.group("src_ip")
        result["user"] = match.group("user")
        result["level"] = "warning"
        result["tags"] = ["auth.failed"]
    elif match := SSH_DISCONNECT_RE.search(body):
        result.update(src_ip=match.group("src_ip"), src_port=safe_int(match.group("port")), user=match.group("user"))

    if result.get("src_ip") and not is_valid_ip(result["src_ip"]):
        result["src_ip"] = None
    if result.get("host") is None and ts_match:
        result["host"] = ts_match.group("host")
    return result


def parse_syslog(line: str) -> dict[str, Any]:
    """解析通用 syslog 文本（RFC3164 / RFC5424）。"""
    if match := SYSLOG_RFC5424_RE.match(line):
        data = match.groupdict()
        pri = safe_int(data.get("pri")) or 13
        return {
            "timestamp": parse_ts(data.get("ts", "")),
            "host": data.get("host"),
            "process": data.get("app"),
            "level": LEVEL_NUM_MAP.get(str(pri % 8), "info"),
            "message": data.get("message", "").strip() or line.strip(),
        }
    if match := SYSLOG_RFC3164_RE.match(line):
        data = match.groupdict()
        return {
            "timestamp": parse_ts(data.get("ts", "")),
            "host": data.get("host"),
            "process": data.get("process"),
            "message": data.get("message", "").strip(),
        }
    ips = extract_ips(line)
    return {
        "timestamp": datetime.now(timezone.utc),
        "src_ip": ips[0] if ips else None,
        "message": line.strip(),
    }


def parse_windows(fields: dict[str, Any], raw: str) -> dict[str, Any]:
    """解析 Windows 事件日志（由 Agent 通过 pywin32 读取后以结构化字段上报）。"""
    level = fields.get("level")
    if isinstance(level, str) and level.isdigit():
        level = int(level)
    event_id = safe_int(fields.get("event_id"))
    src_ip = fields.get("src_ip") or fields.get("IpAddress") or fields.get("ip_address")
    if src_ip in ("-", "::1", "127.0.0.1"):
        src_ip = None if src_ip == "-" else src_ip
    if src_ip and not is_valid_ip(src_ip):
        ips = extract_ips(str(fields.get("message", "")) + " " + raw)
        src_ip = ips[0] if ips else None

    # 依据常见安全事件 ID 推断严重级别
    if level is None:
        if event_id in (1102, 4625, 4719, 4720, 4728, 4732, 4756, 4697):
            level = "warning"
        else:
            level = "info"

    return {
        "timestamp": parse_ts(str(fields.get("timestamp", ""))),
        "host": fields.get("host"),
        "channel": fields.get("channel"),
        "event_id": event_id,
        "level": WINDOWS_LEVEL_MAP.get(level, "info"),
        "user": fields.get("user") or fields.get("TargetUserName") or fields.get("SubjectUserName"),
        "src_ip": src_ip,
        "process": fields.get("process") or fields.get("process_name") or fields.get("NewProcessName"),
        "command": fields.get("command") or fields.get("command_line") or fields.get("ProcessCommandLine"),
        "message": str(fields.get("message", raw))[:8000],
        "tags": fields.get("tags", []),
    }


def build_event(host: str, source_type: str, raw: str, fields: dict[str, Any] | None = None) -> LogEvent:
    """把解析结果组装成统一的 LogEvent 对象。"""
    parsed: dict[str, Any] = dict(fields or {})

    if source_type == "windows":
        parsed = {**parse_windows(parsed, raw), **{k: v for k, v in parsed.items() if v not in (None, "")}}
    elif source_type in ("nginx", "apache"):
        text_parsed = parse_access_log(raw) or (
            parse_nginx_error(raw) if source_type == "nginx" else parse_apache_error(raw)
        ) or parse_syslog(raw)
        parsed = {**text_parsed, **{k: v for k, v in parsed.items() if v not in (None, "")}}
    elif source_type == "ssh":
        parsed = {**parse_ssh(raw), **{k: v for k, v in parsed.items() if v not in (None, "")}}
    elif source_type == "linux":
        parsed = {**parse_ssh(raw), **{k: v for k, v in parsed.items() if v not in (None, "")}}
    else:  # syslog / unknown 走通用解析
        text_parsed = parse_access_log(raw) or parse_syslog(raw)
        parsed = {**text_parsed, **{k: v for k, v in parsed.items() if v not in (None, "")}}

    parsed.setdefault("timestamp", datetime.now(timezone.utc))
    parsed["host"] = parsed.get("host") or host
    parsed["source_type"] = source_type
    parsed["raw"] = raw

    # 过滤掉不属于 LogEvent 的额外字段，避免校验报错
    allowed = set(LogEvent.model_fields.keys())
    clean = {k: v for k, v in parsed.items() if k in allowed}
    clean["tags"] = sorted(set(clean.get("tags") or []))
    clean["level"] = normalize_level(clean.get("level"))
    return LogEvent(**clean)


# 内容特征 -> 日志类型，按优先级从上到下匹配
SOURCE_SIGNATURES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sshd\[\d+\]|Failed password for|Accepted (?:password|publickey) for|Invalid user "), "ssh"),
    (re.compile(r"sudo:|pam_unix\("), "linux"),
    (re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) \S* ?HTTP/1\.[01]"'), "nginx"),
    (re.compile(r"\[Security\]|EventID=\d+|EventRecordID|windows_event_log", re.IGNORECASE), "windows"),
    (re.compile(r"\[(?:error|warn|crit|notice)\]|, client: \d+\.\d+\.\d+\.\d+"), "nginx"),
    (re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ [\w\-/\.]+", re.MULTILINE), "syslog"),
]


def guess_source_type(filename: str, text: str) -> str:
    """根据文件名与内容特征自动识别日志类型，无法识别时返回 unknown。

    优先使用文件名中的明确关键字（可区分 Nginx/Apache 这类解析方式相同的日志），
    其次使用内容特征，最后用文件名兜底，避免误判。
    """
    name = (filename or "").lower()
    if "nginx" in name:
        return "nginx"
    if "apache" in name or "httpd" in name:
        return "apache"
    if name.endswith(".evtx") or "windows" in name or "security" in name:
        return "windows"

    sample = (text or "")[:20000]
    for pattern, source_type in SOURCE_SIGNATURES:
        if pattern.search(sample):
            return source_type

    if "auth" in name or "secure" in name:
        return "ssh"
    if "access" in name or "error" in name:
        return "nginx"
    if "syslog" in name or "message" in name:
        return "syslog"
    return "unknown"

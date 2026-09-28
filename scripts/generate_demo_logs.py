#!/usr/bin/env python3
"""演示数据生成脚本：向 Mini SIEM 推送模拟攻击日志，用于部署后快速验证检测链路。

用法：
    python scripts/generate_demo_logs.py --url http://127.0.0.1:8000 --token change-me-agent-token

会依次模拟：SSH 暴力破解、SQL 注入、目录扫描、Windows 登录爆破、日志清空等场景。
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from datetime import datetime, timedelta, timezone

ATTACKER = "203.0.113.45"
ATTACKER2 = "198.51.100.77"
WEB_HOST = "web-01"
LINUX_HOST = "linux-01"
WIN_HOST = "win-01"


def post(url: str, token: str, host: str, source_type: str, events: list[dict]) -> None:
    """把一批事件推送到服务端。"""
    endpoint = url.rstrip("/") + "/api/v1/ingest"
    payload = json.dumps(
        {"host": host, "source_type": source_type, "events": events}, ensure_ascii=False
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json", "X-Agent-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    print(f"[OK] {source_type:8s} 主机={host:8s} 上报={body.get('accepted')} 新增告警={body.get('alerts')}")


def ssh_lines(count: int = 6) -> list[dict]:
    """生成 SSH 暴力破解日志。"""
    now = datetime.now(timezone.utc) + timedelta(hours=8)
    events = []
    for index in range(count):
        ts = (now + timedelta(seconds=index * 2)).strftime("%b %d %H:%M:%S")
        events.append(
            {"raw": f"{ts} {LINUX_HOST} sshd[1234]: Failed password for root from {ATTACKER} port {51000 + index} ssh2"}
        )
    return events


def web_lines() -> list[dict]:
    """生成 SQL 注入、路径穿越、目录扫描、扫描器 UA 等 Web 攻击日志。"""
    now = datetime.now(timezone.utc) + timedelta(hours=8)
    ts = now.strftime("%d/%b/%Y:%H:%M:%S +0800")
    events = [
        {"raw": f'{ATTACKER} - - [{ts}] "GET /login.php?id=1%27%20union%20select%20user,password%20from%20users-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"'},
        {"raw": f'{ATTACKER} - - [{ts}] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'},
        {"raw": f'{ATTACKER} - - [{ts}] "GET /.env HTTP/1.1" 404 162 "-" "curl/8.0"'},
        {"raw": f'{ATTACKER} - - [{ts}] "GET /index.php?cmd=;cat%20/etc/passwd HTTP/1.1" 500 233 "-" "Mozilla/5.0"'},
        {"raw": f'{ATTACKER} - - [{ts}] "POST /shell.php HTTP/1.1" 200 88 "-" "Mozilla/5.0"'},
    ]
    # 目录扫描：40 次 404
    for index in range(40):
        events.append(
            {"raw": f'{ATTACKER2} - - [{ts}] "GET /admin{index}.php HTTP/1.1" 404 162 "-" "dirbuster/1.0"'}
        )
    return events


def windows_lines() -> list[dict]:
    """生成 Windows 登录爆破、账号创建、日志清空等事件。"""
    now = datetime.now(timezone.utc)
    events = []
    for index in range(6):
        events.append(
            {
                "raw": f"[Security] EventID=4625 TargetUserName: administrator; IpAddress: {ATTACKER}; LogonType: 10; 登录失败",
                "timestamp": (now + timedelta(seconds=index)).isoformat(),
                "fields": {
                    "event_id": 4625,
                    "channel": "Security",
                    "level": 3,
                    "user": "administrator",
                    "src_ip": ATTACKER,
                    "message": f"[Security] EventID=4625 TargetUserName: administrator; IpAddress: {ATTACKER}; LogonType: 10; 登录失败",
                },
            }
        )
    events.append(
        {
            "raw": "[Security] EventID=4720 TargetUserName: backdoor; 新建账号",
            "timestamp": now.isoformat(),
            "fields": {
                "event_id": 4720,
                "channel": "Security",
                "level": 4,
                "user": "backdoor",
                "message": "[Security] EventID=4720 TargetUserName: backdoor; 新建账号",
            },
        }
    )
    events.append(
        {
            "raw": "[Security] EventID=1102 审计日志已被清除",
            "timestamp": now.isoformat(),
            "fields": {
                "event_id": 1102,
                "channel": "Security",
                "level": 4,
                "user": "administrator",
                "message": "[Security] EventID=1102 审计日志已被清除",
            },
        }
    )
    return events


def main() -> int:
    """命令行入口：按场景推送演示日志。"""
    parser = argparse.ArgumentParser(description="Mini SIEM 演示日志生成器")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="服务端地址")
    parser.add_argument("--token", default="change-me-agent-token", help="Agent 令牌")
    args = parser.parse_args()

    post(args.url, args.token, LINUX_HOST, "ssh", ssh_lines())
    post(args.url, args.token, WEB_HOST, "nginx", web_lines())
    post(args.url, args.token, WIN_HOST, "windows", windows_lines())
    print("演示数据推送完成，请等待约 10 秒后在 Dashboard 查看告警。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

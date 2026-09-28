"""网络相关工具函数：IP 校验、内网判断、IP 提取。"""
from __future__ import annotations

import ipaddress
import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")


def is_valid_ip(value: str | None) -> bool:
    """判断字符串是否为合法 IP 地址（IPv4/IPv6）。"""
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_internal_ip(value: str | None) -> bool:
    """判断是否为内网/保留地址。"""
    if not is_valid_ip(value):
        return False
    ip = ipaddress.ip_address(value.strip())
    return ip.is_private or ip.is_loopback or ip.is_link_local


def extract_ips(text: str) -> list[str]:
    """从文本中提取全部 IP 地址（按出现顺序去重）。"""
    result: list[str] = []
    for match in IP_RE.findall(text or ""):
        if is_valid_ip(match) and match not in result:
            result.append(match)
    return result

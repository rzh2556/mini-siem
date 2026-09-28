"""API 通用工具：鉴权依赖、时间解析、查询构造。"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Header, HTTPException, status

from app.config import settings

RELATIVE_RE = re.compile(r"^(?P<num>\d+)(?P<unit>[smhd])$")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_time(value: str | None) -> datetime | None:
    """解析时间参数，支持 ISO8601 与相对时间（如 30m、24h、7d）。"""
    if not value:
        return None
    value = value.strip()
    if match := RELATIVE_RE.match(value):
        seconds = int(match.group("num")) * UNIT_SECONDS[match.group("unit")]
        return datetime.now(timezone.utc) - timedelta(seconds=seconds)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def time_range_filter(field: str, start: datetime | None, end: datetime | None) -> dict[str, Any] | None:
    """构造时间范围查询片段。"""
    if not start and not end:
        return None
    bounds: dict[str, str] = {}
    if start:
        bounds["gte"] = start.astimezone(timezone.utc).isoformat()
    if end:
        bounds["lte"] = end.astimezone(timezone.utc).isoformat()
    return {"range": {field: bounds}}


def parse_page(size: int, maximum: int = 200) -> int:
    """限制分页大小，防止单次拉取过多数据。"""
    return max(1, min(size, maximum))


async def require_agent_token(x_agent_token: str = Header(default="")) -> None:
    """校验 Agent 上报令牌。"""
    if settings.agent_token and x_agent_token != settings.agent_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent 令牌无效")


async def require_api_token(authorization: str = Header(default="")) -> None:
    """校验前端/API 访问令牌（未配置时放行）。"""
    if not settings.api_token:
        return
    token = authorization.removeprefix("Bearer").strip()
    if token != settings.api_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="访问令牌无效")

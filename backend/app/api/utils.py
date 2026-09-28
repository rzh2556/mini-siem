"""API 通用工具：鉴权依赖、时间解析、查询构造。"""
from __future__ import annotations

import hmac
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Header, HTTPException, status

from app.config import settings
from app.state import state

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


def _bearer_token(authorization: str) -> str:
    """从 Authorization 头中提取 Bearer 令牌。"""
    return authorization.removeprefix("Bearer").strip()


async def require_agent_token(x_agent_token: str = Header(default="")) -> None:
    """校验 Agent 上报令牌（与后台登录账号相互独立）。"""
    if settings.agent_token and not hmac.compare_digest(x_agent_token or "", settings.agent_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent 令牌无效")


async def require_admin(authorization: str = Header(default="")) -> str:
    """要求管理员登录：校验 JWT，返回登录用户名。"""
    token = _bearer_token(authorization)
    if not token or state.system is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录")
    username = state.system.verify_token(token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="登录已过期，请重新登录"
        )
    return username


async def require_api_token(authorization: str = Header(default="")) -> str:
    """前端/API 访问鉴权：接受管理员登录 JWT，或配置的静态 API_TOKEN。"""
    token = _bearer_token(authorization)
    if token and state.system is not None:
        username = state.system.verify_token(token)
        if username:
            return username
    if settings.api_token and token and hmac.compare_digest(token, settings.api_token):
        return "__api_token__"
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录或提供有效的访问令牌")

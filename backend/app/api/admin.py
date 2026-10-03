"""管理后台接口：运行参数查看/修改、采集令牌重置、系统信息。"""
from __future__ import annotations

import logging
import platform
import secrets
import socket
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends

from app import __version__
from app.api.utils import require_admin
from app.config import settings
from app.models.schemas import SettingsUpdate
from app.state import state
from app.system.env_file import default_env_path, update_env_file
from app.system.store import EDITABLE_SETTINGS

router = APIRouter(prefix="/admin", tags=["管理后台"], dependencies=[Depends(require_admin)])

logger = logging.getLogger(__name__)

# 修改后需要重启服务才能完全生效的配置项（其余保存后即时生效）
RESTART_REQUIRED_KEYS = {"cors_origins", "geoip_db_path"}
_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_PROCESS_STARTED_AT = time.time()


def _current_settings() -> dict[str, Any]:
    """读取当前运行参数（含后台覆盖后的实时值）。"""
    return {key: getattr(settings, key) for key in EDITABLE_SETTINGS}


def _read_only_settings() -> dict[str, Any]:
    """读取不允许在后台直接修改、只能通过部署配置调整的参数（仅展示）。"""
    return {
        "storage_backend": settings.storage_backend,
        "sqlite_path": settings.sqlite_path,
        "es_url": settings.es_url,
        "frontend_dist": settings.frontend_dist or "",
        "rules_dir": settings.rules_dir,
        "system_db_path": settings.system_db_path,
        "admin_username": settings.admin_username,
        "token_expire_hours": settings.token_expire_hours,
    }


def _file_size(path_text: str) -> int:
    """统计数据库文件及其 WAL 文件的总字节数，路径不存在时返回 0。"""
    path = Path(path_text)
    total = 0
    for suffix in ("", "-wal", "-shm"):
        target = Path(str(path) + suffix)
        if target.exists():
            total += target.stat().st_size
    return total


@router.get("/settings", summary="获取系统运行参数")
async def get_settings() -> dict[str, Any]:
    """返回可编辑参数当前值、只读部署参数，以及需重启生效的键名列表。"""
    return {
        "editable": _current_settings(),
        "read_only": _read_only_settings(),
        "restart_required_keys": sorted(RESTART_REQUIRED_KEYS),
    }


@router.put("/settings", summary="保存系统运行参数")
async def update_settings(payload: SettingsUpdate) -> dict[str, Any]:
    """保存运行参数：能热生效的立即生效，部分参数提示需重启。"""
    assert state.system is not None
    changes = payload.model_dump(exclude_none=True)
    if "log_level" in changes and changes["log_level"].upper() not in _VALID_LOG_LEVELS:
        changes["log_level"] = "INFO"

    restart_hint = False
    for key, value in changes.items():
        setattr(settings, key, value)
        state.system.set_value(key, value)
        if key in RESTART_REQUIRED_KEYS:
            restart_hint = True

    # ---- 热生效到运行期组件 ----
    if state.aggregator is not None:
        if "alert_cooldown" in changes:
            state.aggregator.cooldown = settings.alert_cooldown
        if "min_alert_severity" in changes:
            state.aggregator.min_severity = settings.min_alert_severity
        if "ip_whitelist" in changes:
            state.aggregator.whitelist = settings.whitelist_ips
        if "ignore_internal_src" in changes:
            state.aggregator.ignore_internal = settings.ignore_internal_src
    if state.geoip is not None and "geoip_online_fallback" in changes:
        state.geoip.online_fallback = settings.geoip_online_fallback
    if "log_level" in changes:
        logging.getLogger().setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))

    # 同步回写 .env：方便直接在文件中查看与备份；不可写时仅记录日志，不影响系统库中的保存结果
    env_written = update_env_file(default_env_path(), changes)

    logger.info("管理员更新了 %d 项运行参数：%s", len(changes), ", ".join(changes))
    hints = ["配置已保存"]
    if env_written:
        hints.append("已同步到 .env")
    if restart_hint:
        hints.append("部分参数需重启服务后生效")
    return {
        "message": "，".join(hints),
        "restart_required": restart_hint,
        "editable": _current_settings(),
    }


@router.post("/agent-token/regenerate", summary="重新生成 Agent 采集令牌")
async def regenerate_agent_token() -> dict[str, str]:
    """生成新的随机采集令牌并立即生效，旧令牌同时失效。"""
    assert state.system is not None
    token = secrets.token_urlsafe(32)
    settings.agent_token = token
    state.system.set_value("agent_token", token)
    # 同步回写 .env，避免重启后又用回旧令牌
    update_env_file(default_env_path(), {"agent_token": token})
    logger.info("管理员重新生成了 Agent 采集令牌")
    return {"agent_token": token, "message": "新令牌已生效，请同步更新各 Agent 的 config.yml"}


@router.get("/system", summary="获取系统信息")
async def system_info() -> dict[str, Any]:
    """返回版本、主机、运行时长、存储状态与数据库占用等运维信息。"""
    storage_ok = await state.storage.ping() if state.storage else False
    return {
        "version": __version__,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "backend": settings.storage_backend,
        "storage_ok": storage_ok,
        "rules_loaded": len(state.loader.rules) if state.loader else 0,
        "rules_enabled": len(state.engine.rules) if state.engine else 0,
        "uptime_seconds": int(time.time() - _PROCESS_STARTED_AT),
        "business_db_bytes": _file_size(settings.sqlite_path),
        "system_db_bytes": _file_size(settings.system_db_path),
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S %z"),
    }

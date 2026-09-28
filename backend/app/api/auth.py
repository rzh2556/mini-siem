"""管理员认证接口：登录、当前用户信息、修改密码。"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from app.api.utils import require_admin
from app.models.schemas import ChangePasswordRequest, LoginRequest, LoginResponse
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["认证"])

# 新密码最低长度，前后端共用同一份约束，避免规则漂移
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def _validate_new_password(password: str) -> None:
    """校验新密码复杂度：长度 8~128，且不能包含空白字符。"""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"新密码至少 {MIN_PASSWORD_LENGTH} 位")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"新密码不能超过 {MAX_PASSWORD_LENGTH} 位")
    if any(ch.isspace() for ch in password):
        raise HTTPException(status_code=400, detail="新密码不能包含空格")


@router.post("/login", response_model=LoginResponse, summary="管理员登录")
async def login(payload: LoginRequest) -> LoginResponse:
    """校验账号密码并签发 JWT。"""
    if state.system is None:
        raise HTTPException(status_code=503, detail="系统尚未初始化完成")
    user = state.system.authenticate(payload.username.strip(), payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    token, expires_at = state.system.issue_token(user["username"])
    logger.info("管理员登录成功：%s", user["username"])
    return LoginResponse(
        access_token=token,
        expires_at=expires_at,
        username=user["username"],
        must_change_password=user["must_change"],
    )


@router.get("/me", summary="当前登录用户")
async def me(username: str = Depends(require_admin)) -> dict[str, object]:
    """返回当前登录用户名（前端用于校验令牌是否仍然有效）。"""
    return {"username": username}


@router.post("/change-password", summary="修改当前账号密码")
async def change_password(
    payload: ChangePasswordRequest, username: str = Depends(require_admin)
) -> dict[str, str]:
    """凭旧密码设置新密码，成功后旧令牌仍有效，可用新密码重新登录。"""
    _validate_new_password(payload.new_password)
    if payload.old_password == payload.new_password:
        raise HTTPException(status_code=400, detail="新密码不能与旧密码相同")
    assert state.system is not None
    if not state.system.change_password(username, payload.old_password, payload.new_password):
        raise HTTPException(status_code=400, detail="原密码不正确")
    logger.info("管理员 %s 已修改登录密码", username)
    return {"message": "密码修改成功"}

"""检测规则管理接口。"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.api.utils import require_api_token
from app.engine.rule_loader import rule_to_dict
from app.models.schemas import RuleUpdate
from app.state import state

router = APIRouter(prefix="/rules", tags=["规则"], dependencies=[Depends(require_api_token)])


@router.get("", summary="获取规则列表")
async def list_rules() -> dict[str, Any]:
    """返回全部已加载规则及其启停状态。"""
    rules = [rule_to_dict(rule) for rule in state.loader.rules]
    return {
        "total": len(rules),
        "enabled": sum(1 for r in rules if r["enabled"]),
        "items": rules,
    }


@router.patch("/{rule_id}", summary="调整规则配置")
async def update_rule(rule_id: str, payload: RuleUpdate) -> dict[str, Any]:
    """在线启停规则、调整等级或阈值，并立即生效。"""
    rule = state.loader.update(rule_id, payload.enabled, payload.severity, payload.threshold)
    if rule is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    state.engine.set_rules(state.loader.rules)
    return rule_to_dict(rule)


@router.post("/reload", summary="重新加载规则")
async def reload_rules() -> dict[str, Any]:
    """从磁盘重新加载规则文件（修改 YAML 后无需重启服务）。"""
    count = state.pipeline.reload_rules()
    return {"loaded": count}

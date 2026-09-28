"""检测规则管理接口：查询、在线调整、后台自定义规则的增删改。"""
from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.api.utils import require_admin, require_api_token
from app.engine.rule_loader import rule_to_dict
from app.models.schemas import Rule, RuleUpdate
from app.state import state

router = APIRouter(prefix="/rules", tags=["规则"], dependencies=[Depends(require_api_token)])

# 自定义规则 ID 只允许小写字母、数字、中划线与下划线，防止异常字符写入文件名或日志
RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


def _rule_payload(rule: Rule) -> dict[str, Any]:
    """在规则序列化结果上补充“是否为自定义规则”标记。"""
    data = rule_to_dict(rule)
    data["managed"] = state.loader.is_managed(rule.id)
    return data


def _refresh_engine() -> None:
    """把加载器中的最新规则同步到匹配引擎。"""
    state.engine.set_rules(state.loader.rules)


@router.get("", summary="获取规则列表")
async def list_rules() -> dict[str, Any]:
    """返回全部已加载规则及其启停状态。"""
    rules = [_rule_payload(rule) for rule in state.loader.rules]
    return {
        "total": len(rules),
        "enabled": sum(1 for r in rules if r["enabled"]),
        "items": rules,
    }


@router.post("", summary="新增自定义规则", dependencies=[Depends(require_admin)])
async def create_rule(payload: Rule) -> dict[str, Any]:
    """在后台新增一条自定义规则，持久化到 custom_managed.yml 并立即生效。"""
    if not RULE_ID_RE.match(payload.id):
        raise HTTPException(status_code=400, detail="规则 ID 需为 2~64 位小写字母、数字、中划线或下划线")
    if any(rule.id == payload.id for rule in state.loader.rules):
        raise HTTPException(status_code=409, detail=f"规则 ID 已存在：{payload.id}")
    if not payload.all_of and not payload.any_of:
        raise HTTPException(status_code=400, detail="请至少配置一个匹配条件（all_of 或 any_of）")
    try:
        rule = state.loader.upsert_managed(payload)
    except Exception as exc:  # 写盘/加载失败时返回明确错误，不吞异常
        raise HTTPException(status_code=500, detail=f"规则保存失败：{exc}") from exc
    _refresh_engine()
    return _rule_payload(rule)


@router.put("/{rule_id}", summary="修改自定义规则", dependencies=[Depends(require_admin)])
async def replace_rule(rule_id: str, payload: Rule) -> dict[str, Any]:
    """整体更新一条后台自定义规则；内置规则不允许在此修改。"""
    if payload.id != rule_id:
        raise HTTPException(status_code=400, detail="请求体中的规则 ID 与路径不一致")
    if not state.loader.is_managed(rule_id):
        raise HTTPException(status_code=400, detail="内置规则仅支持启停与等级/阈值调整，不能整体修改")
    if not payload.all_of and not payload.any_of:
        raise HTTPException(status_code=400, detail="请至少配置一个匹配条件（all_of 或 any_of）")
    try:
        rule = state.loader.upsert_managed(payload)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"规则保存失败：{exc}") from exc
    _refresh_engine()
    return _rule_payload(rule)


@router.delete("/{rule_id}", summary="删除自定义规则", dependencies=[Depends(require_admin)])
async def delete_rule(rule_id: str) -> dict[str, bool]:
    """删除一条后台自定义规则；内置规则不允许删除。"""
    if not state.loader.is_managed(rule_id):
        raise HTTPException(status_code=400, detail="内置规则不能删除，可在列表中停用")
    if not state.loader.delete_managed(rule_id):
        raise HTTPException(status_code=404, detail="规则不存在")
    _refresh_engine()
    return {"deleted": True}


@router.patch("/{rule_id}", summary="调整规则配置")
async def update_rule(rule_id: str, payload: RuleUpdate) -> dict[str, Any]:
    """在线启停规则、调整等级或阈值，并立即生效。"""
    rule = state.loader.update(rule_id, payload.enabled, payload.severity, payload.threshold)
    if rule is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    _refresh_engine()
    return _rule_payload(rule)


@router.post("/reload", summary="重新加载规则")
async def reload_rules() -> dict[str, Any]:
    """从磁盘重新加载规则文件（修改 YAML 后无需重启服务）。"""
    count = state.pipeline.reload_rules()
    return {"loaded": count}

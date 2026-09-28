"""告警管理接口：查询、详情、状态流转、批量处理。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.utils import parse_page, parse_time, require_api_token, time_range_filter
from app.models.schemas import AlertUpdate, BulkAlertUpdate, SearchResult
from app.state import state

router = APIRouter(prefix="/alerts", tags=["告警"], dependencies=[Depends(require_api_token)])


@router.get("", response_model=SearchResult, summary="查询告警列表")
async def list_alerts(
    status_: str | None = Query(default=None, alias="status", description="open/acknowledged/closed"),
    severity: str | None = None,
    rule_id: str | None = None,
    src_ip: str | None = None,
    host: str | None = None,
    user: str | None = None,
    keyword: str | None = Query(default=None, description="按告警名称/描述模糊搜索"),
    time_from: str | None = Query(default=None, alias="from"),
    time_to: str | None = Query(default=None, alias="to"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=200),
) -> dict[str, Any]:
    """按条件分页查询告警，默认按最近发生时间倒序。"""
    filters: list[dict[str, Any]] = []
    for field, value in (
        ("status", status_),
        ("severity", severity),
        ("rule_id", rule_id),
        ("src_ip", src_ip),
        ("host", host),
        ("user", user),
    ):
        if value:
            filters.append({"term": {field: value}})
    if time_filter := time_range_filter("last_seen", parse_time(time_from), parse_time(time_to)):
        filters.append(time_filter)

    must: list[dict[str, Any]] = []
    if keyword:
        must.append(
            {
                "multi_match": {
                    "query": keyword,
                    "fields": ["rule_name", "description"],
                    "operator": "and",
                }
            }
        )

    resp = await state.storage.search(
        index=state.storage.alert_index,
        query={"bool": {"filter": filters, "must": must}},
        sort=[{"last_seen": {"order": "desc"}}],
        page=page,
        size=parse_page(size),
    )
    items = [{"id": hit["_id"], **hit["_source"]} for hit in resp["hits"]["hits"]]
    return {"total": resp["hits"]["total"]["value"], "items": items}


@router.get("/{alert_id}", summary="告警详情")
async def get_alert(alert_id: str) -> dict[str, Any]:
    """获取单条告警详情（含原始日志样本）。"""
    alert = await state.storage.get_doc(state.storage.alert_index, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")
    return alert


@router.patch("/{alert_id}", summary="更新告警状态")
async def update_alert(alert_id: str, payload: AlertUpdate) -> dict[str, Any]:
    """更新告警处理状态与备注（open/acknowledged/closed）。"""
    patch: dict[str, Any] = {"updated_at": datetime.now(timezone.utc).isoformat()}
    if payload.status:
        patch["status"] = payload.status
    if payload.comment is not None:
        patch["ack_comment"] = payload.comment
    if not await state.storage.update_alert(alert_id, patch):
        raise HTTPException(status_code=404, detail="告警不存在")
    return await state.storage.get_doc(state.storage.alert_index, alert_id)


@router.post("/bulk", summary="批量更新告警状态")
async def bulk_update(payload: BulkAlertUpdate) -> dict[str, Any]:
    """批量修改告警状态，用于一键处理同类告警。"""
    query = {"terms": {"_id": payload.ids}}
    script = {
        "source": "ctx._source.status = params.status; ctx._source.updated_at = params.now;",
        "lang": "painless",
        "params": {"status": payload.status, "now": datetime.now(timezone.utc).isoformat()},
    }
    updated = await state.storage.update_by_query(state.storage.alert_index, query, script)
    return {"updated": updated}

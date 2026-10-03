"""日志检索接口。"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.utils import parse_page, parse_time, require_admin, require_api_token, time_range_filter
from app.models.schemas import DeleteResult, SearchResult, UploadBatchList
from app.state import state

router = APIRouter(prefix="/logs", tags=["日志"], dependencies=[Depends(require_api_token)])

SORT_FIELDS = {"timestamp", "status_code", "src_ip", "host"}


@router.get("/search", response_model=SearchResult, summary="检索日志")
async def search_logs(
    q: str | None = Query(default=None, description="全文关键字，支持 AND/OR/NOT"),
    source_type: str | None = None,
    host: str | None = None,
    src_ip: str | None = None,
    user: str | None = None,
    level: str | None = None,
    status_code: int | None = None,
    matched_rule: str | None = Query(default=None, description="按命中的规则 ID 过滤"),
    time_from: str | None = Query(default=None, alias="from", description="起始时间，支持 24h 或 ISO 时间"),
    time_to: str | None = Query(default=None, alias="to"),
    sort: str = Query(default="timestamp"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=200),
) -> dict[str, Any]:
    """按多条件检索归一化日志，返回分页结果。"""
    filters: list[dict[str, Any]] = []
    for field, value in (
        ("source_type", source_type),
        ("host", host),
        ("src_ip", src_ip),
        ("user", user),
        ("level", level),
    ):
        if value:
            filters.append({"term": {field: value}})
    if status_code is not None:
        filters.append({"term": {"status_code": status_code}})
    if matched_rule:
        filters.append({"term": {"matched_rules": matched_rule}})
    if time_filter := time_range_filter("@timestamp", parse_time(time_from), parse_time(time_to)):
        filters.append(time_filter)

    must: list[dict[str, Any]] = []
    if q:
        must.append(
            {
                "simple_query_string": {
                    "query": q,
                    "fields": ["message^2", "url", "command", "user_agent"],
                    "default_operator": "and",
                }
            }
        )

    query = {"bool": {"filter": filters, "must": must}}
    sort_field = "@timestamp" if sort == "timestamp" else sort
    resp = await state.storage.search(
        index=state.storage.log_index_pattern,
        query=query,
        sort=[{sort_field: {"order": order}}],
        page=page,
        size=parse_page(size),
    )

    items: list[dict[str, Any]] = []
    for hit in resp["hits"]["hits"]:
        doc = dict(hit["_source"])
        doc["id"] = hit["_id"]
        if "@timestamp" in doc:
            doc["timestamp"] = doc.pop("@timestamp")
        items.append(doc)
    return {"total": resp["hits"]["total"]["value"], "items": items}


@router.get("/filters", summary="获取检索筛选项")
async def log_filters(hours: int = Query(default=24, ge=1, le=720)) -> dict[str, Any]:
    """返回最近一段时间内出现过的日志类型、主机、等级，供前端下拉框使用。"""
    start = parse_time(f"{hours}h")
    query = {"range": {"@timestamp": {"gte": start.isoformat()}}}
    aggs = {
        "source_types": {"terms": {"field": "source_type", "size": 20}},
        "hosts": {"terms": {"field": "host", "size": 50}},
        "levels": {"terms": {"field": "level", "size": 10}},
    }
    resp = await state.storage.search(
        index=state.storage.log_index_pattern, query=query, size=0, aggs=aggs
    )
    buckets = resp.get("aggregations", {})
    return {
        "source_types": [b["key"] for b in buckets.get("source_types", {}).get("buckets", [])],
        "hosts": [b["key"] for b in buckets.get("hosts", {}).get("buckets", [])],
        "levels": [b["key"] for b in buckets.get("levels", {}).get("buckets", [])],
    }


@router.get("/uploads", response_model=UploadBatchList, summary="列出日志上传批次")
async def list_upload_batches(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    """返回历史日志文件上传记录，供按批次整体删除某次上传的日志。"""
    return await state.storage.list_upload_batches(page=page, size=size)


@router.delete("/uploads/{batch_id}", response_model=DeleteResult, summary="删除整批上传日志")
async def delete_upload_batch(
    batch_id: str, _: str = Depends(require_admin)
) -> dict[str, Any]:
    """删除某次上传文件产生的全部日志，批次记录一并移除。"""
    deleted = await state.storage.delete_upload_batch(batch_id)
    return {"deleted": deleted}


@router.delete("/{log_id}", response_model=DeleteResult, summary="删除单条日志")
async def delete_log(log_id: str, _: str = Depends(require_admin)) -> dict[str, Any]:
    """按日志 ID 删除单条日志。"""
    if not await state.storage.delete_log(log_id):
        raise HTTPException(status_code=404, detail="日志不存在或已被删除")
    return {"deleted": 1}

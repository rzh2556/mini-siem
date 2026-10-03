"""统计接口：总览指标、时间趋势、攻击地图数据。"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query

from app.api.utils import parse_time, require_api_token
from app.state import state

router = APIRouter(prefix="/stats", tags=["统计"], dependencies=[Depends(require_api_token)])

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
ALLOWED_INTERVALS = {"10m", "30m", "1h", "3h", "6h", "12h", "1d"}


@router.get("/overview", summary="总览指标")
async def overview(hours: int = Query(default=24, ge=1, le=720)) -> dict[str, Any]:
    """返回仪表盘顶部指标卡与 TOP 排行榜数据。"""
    start = parse_time(f"{hours}h")
    log_query = {"range": {"@timestamp": {"gte": start.isoformat()}}}
    alert_window = {"range": {"first_seen": {"gte": start.isoformat()}}}
    storage = state.storage

    (
        log_total,
        alerts_resp,
        open_alerts,
        top_src_ips,
        top_countries,
        source_types,
        hosts,
    ) = await asyncio.gather(
        storage.count(storage.log_index_pattern, log_query),
        storage.search(
            index=storage.alert_index,
            query=alert_window,
            size=0,
            aggs={
                "by_severity": {"terms": {"field": "severity", "size": 10}},
                "by_rule": {"terms": {"field": "rule_name", "size": 10}},
                "by_status": {"terms": {"field": "status", "size": 10}},
            },
        ),
        # 与 alerts_total 使用同一时间窗口，避免同一页面两个指标口径不一致
        storage.count(
            storage.alert_index,
            {"bool": {"filter": [{"term": {"status": "open"}}, alert_window]}},
        ),
        storage.search(
            index=storage.alert_index,
            query=alert_window,
            size=0,
            aggs={
                "top": {
                    "terms": {"field": "src_ip", "size": 10},
                    "aggs": {
                        "country": {"terms": {"field": "geo.country_code", "size": 1}},
                        "severity": {"terms": {"field": "severity", "size": 1}},
                    },
                }
            },
        ),
        storage.search(
            index=storage.alert_index,
            query=alert_window,
            size=0,
            aggs={"top": {"terms": {"field": "geo.country_code", "size": 10}}},
        ),
        storage.search(
            index=storage.log_index_pattern,
            query=log_query,
            size=0,
            aggs={"top": {"terms": {"field": "source_type", "size": 10}}},
        ),
        storage.search(
            index=storage.log_index_pattern,
            query=log_query,
            size=0,
            aggs={"top": {"terms": {"field": "host", "size": 10}}},
        ),
    )

    agg = alerts_resp.get("aggregations", {})
    severity_buckets = {
        b["key"]: b["doc_count"] for b in agg.get("by_severity", {}).get("buckets", [])
    }

    top_ips = []
    for bucket in top_src_ips.get("aggregations", {}).get("top", {}).get("buckets", []):
        country_buckets = bucket.get("country", {}).get("buckets", [])
        severity_buckets_ = bucket.get("severity", {}).get("buckets", [])
        top_ips.append(
            {
                "src_ip": bucket["key"],
                "count": bucket["doc_count"],
                "country_code": country_buckets[0]["key"] if country_buckets else None,
                "severity": severity_buckets_[0]["key"] if severity_buckets_ else None,
            }
        )

    return {
        "hours": hours,
        "logs_total": log_total,
        "alerts_total": alerts_resp["hits"]["total"]["value"],
        "open_alerts": open_alerts,
        "severity_distribution": {
            level: severity_buckets.get(level, 0) for level in ("critical", "high", "medium", "low")
        },
        "top_rules": [
            {"name": b["key"], "count": b["doc_count"]}
            for b in agg.get("by_rule", {}).get("buckets", [])
        ],
        "status_distribution": {
            b["key"]: b["doc_count"] for b in agg.get("by_status", {}).get("buckets", [])
        },
        "top_src_ips": top_ips,
        "top_countries": [
            {"country_code": b["key"], "count": b["doc_count"]}
            for b in top_countries.get("aggregations", {}).get("top", {}).get("buckets", [])
        ],
        "source_types": [
            {"name": b["key"], "count": b["doc_count"]}
            for b in source_types.get("aggregations", {}).get("top", {}).get("buckets", [])
        ],
        "hosts": [
            {"name": b["key"], "count": b["doc_count"]}
            for b in hosts.get("aggregations", {}).get("top", {}).get("buckets", [])
        ],
    }


@router.get("/timeline", summary="日志与告警时间趋势")
async def timeline(
    hours: int = Query(default=24, ge=1, le=720),
    interval: str = Query(default="1h"),
) -> dict[str, Any]:
    """返回按时间分桶的日志量与告警量，用于折线图展示。"""
    if interval not in ALLOWED_INTERVALS:
        interval = "1h"
    start = parse_time(f"{hours}h")
    end = datetime.now(timezone.utc)
    bounds = {"min": start.isoformat(), "max": end.isoformat()}
    storage = state.storage

    logs_resp, alerts_resp = await asyncio.gather(
        storage.search(
            index=storage.log_index_pattern,
            query={"range": {"@timestamp": {"gte": start.isoformat()}}},
            size=0,
            aggs={
                "series": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": interval,
                        "min_doc_count": 0,
                        "extended_bounds": bounds,
                    }
                }
            },
        ),
        storage.search(
            index=storage.alert_index,
            query={"range": {"first_seen": {"gte": start.isoformat()}}},
            size=0,
            aggs={
                "series": {
                    "date_histogram": {
                        "field": "first_seen",
                        "fixed_interval": interval,
                        "min_doc_count": 0,
                        "extended_bounds": bounds,
                    },
                    "aggs": {"hits": {"sum": {"field": "count"}}},
                }
            },
        ),
    )

    alert_map = {
        b["key"]: int(b.get("hits", {}).get("value", 0))
        for b in alerts_resp.get("aggregations", {}).get("series", {}).get("buckets", [])
    }
    points = []
    for bucket in logs_resp.get("aggregations", {}).get("series", {}).get("buckets", []):
        ts = datetime.fromtimestamp(bucket["key"] / 1000, tz=timezone.utc)
        points.append(
            {
                "time": ts.isoformat(),
                "logs": bucket["doc_count"],
                "alerts": alert_map.get(bucket["key"], 0),
            }
        )
    return {"interval": interval, "points": points}


@router.get("/geo", summary="攻击地图数据")
async def geo_map(
    hours: int = Query(default=72, ge=1, le=720),
    limit: int = Query(default=500, ge=1, le=2000),
) -> dict[str, Any]:
    """返回带地理坐标的攻击源汇总，用于世界地图打点与攻击链路展示。"""
    start = parse_time(f"{hours}h")
    storage = state.storage
    resp = await storage.search(
        index=storage.alert_index,
        query={
            "bool": {
                "filter": [
                    {"range": {"last_seen": {"gte": start.isoformat()}}},
                    {"exists": {"field": "geo.lat"}},
                ]
            }
        },
        sort=[{"last_seen": {"order": "desc"}}],
        page=1,
        size=limit,
    )

    points: dict[str, dict[str, Any]] = {}
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        ip = src.get("src_ip") or hit["_id"]
        geo = src.get("geo") or {}
        entry = points.setdefault(
            ip,
            {
                "src_ip": ip,
                "country": geo.get("country"),
                "country_code": geo.get("country_code"),
                "city": geo.get("city"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "count": 0,
                "severity": src.get("severity", "low"),
                "rules": [],
                "last_seen": src.get("last_seen"),
                "hosts": [],
            },
        )
        entry["count"] += int(src.get("count", 1))
        if SEVERITY_ORDER.get(src.get("severity", "low"), 0) > SEVERITY_ORDER.get(entry["severity"], 0):
            entry["severity"] = src.get("severity")
        if src.get("rule_name") and src["rule_name"] not in entry["rules"]:
            entry["rules"].append(src["rule_name"])
        if src.get("host") and src["host"] not in entry["hosts"]:
            entry["hosts"].append(src["host"])
        if src.get("last_seen") and src["last_seen"] > (entry["last_seen"] or ""):
            entry["last_seen"] = src["last_seen"]

    attackers = sorted(points.values(), key=lambda x: x["count"], reverse=True)
    return {
        "total": sum(p["count"] for p in attackers),
        "attackers": attackers,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/attackers", summary="攻击源排行榜")
async def attackers(
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    """按告警次数排名攻击源 IP，并附带被攻击主机与命中规则。"""
    start = parse_time(f"{hours}h")
    storage = state.storage
    resp = await storage.search(
        index=storage.alert_index,
        query={"range": {"last_seen": {"gte": start.isoformat()}}},
        size=0,
        aggs={
            "top": {
                "terms": {"field": "src_ip", "size": limit},
                "aggs": {
                    "hosts": {"terms": {"field": "host", "size": 5}},
                    "rules": {"terms": {"field": "rule_name", "size": 5}},
                    "country": {"terms": {"field": "geo.country_code", "size": 1}},
                    "severity": {"terms": {"field": "severity", "size": 1}},
                    "last": {"max": {"field": "last_seen"}},
                },
            }
        },
    )
    result = []
    for bucket in resp.get("aggregations", {}).get("top", {}).get("buckets", []):
        result.append(
            {
                "src_ip": bucket["key"],
                "count": bucket["doc_count"],
                "hosts": [b["key"] for b in bucket.get("hosts", {}).get("buckets", [])],
                "rules": [b["key"] for b in bucket.get("rules", {}).get("buckets", [])],
                "country_code": (bucket.get("country", {}).get("buckets") or [{}])[0].get("key"),
                "severity": (bucket.get("severity", {}).get("buckets") or [{}])[0].get("key"),
                "last_seen": bucket.get("last", {}).get("value_as_string"),
            }
        )
    return {"hours": hours, "items": result}

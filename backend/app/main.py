"""FastAPI 应用入口：初始化组件、注册路由、启动后台维护任务。"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api import alerts, ingest, logs, rules, stats
from app.config import settings
from app.engine.aggregator import AlertAggregator
from app.engine.geoip import GeoIPResolver
from app.engine.matcher import RuleEngine
from app.engine.pipeline import IngestPipeline
from app.engine.rule_loader import RuleLoader
from app.state import state
from app.storage.es_client import ESStorage
from app.storage.sqlite_client import SQLiteStorage

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("mini-siem")

MAINTENANCE_INTERVAL = 60
_cleanup_counter = 0


async def _maintenance_loop() -> None:
    """后台维护任务：等待存储就绪、初始化表结构、热加载规则、定期清理数据。"""
    global _cleanup_counter
    storage_ready = False
    while True:
        try:
            if not storage_ready:
                storage_ready = await state.storage.ping()
                if not storage_ready:
                    logger.warning("存储后端未就绪，%s 秒后重试", MAINTENANCE_INTERVAL)
                else:
                    await state.storage.ensure_indices()
                    logger.info("存储后端就绪（%s）", settings.storage_backend)

            state.pipeline.prune_state()

            if state.loader.reload_if_changed():
                state.engine.set_rules(state.loader.rules)
                logger.info("检测到规则文件变更，已自动热加载")

            _cleanup_counter += MAINTENANCE_INTERVAL
            if _cleanup_counter >= 3600:
                _cleanup_counter = 0
                await state.storage.cleanup_old_indices()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # 后台任务异常不应中断服务
            logger.error("后台维护任务异常: %s", exc)
            storage_ready = False
        await asyncio.sleep(MAINTENANCE_INTERVAL)


def build_storage() -> ESStorage | SQLiteStorage:
    """按配置创建存储后端：默认 SQLite（零依赖、低负载），可选 Elasticsearch。"""
    if settings.storage_backend.strip().lower() == "elasticsearch":
        logger.info("存储后端：Elasticsearch（%s）", settings.es_url)
        return ESStorage(settings.es_url, settings.es_index_prefix, settings.es_retention_days)
    logger.info("存储后端：SQLite（%s）", settings.sqlite_path)
    return SQLiteStorage(settings.sqlite_path, settings.es_index_prefix, settings.es_retention_days)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理：启动时装配组件，关闭时释放资源。"""
    storage = build_storage()
    loader = RuleLoader(settings.rules_dir)
    engine = RuleEngine()
    engine.set_rules(loader.load())
    aggregator = AlertAggregator(
        cooldown=settings.alert_cooldown,
        whitelist=settings.whitelist_ips,
        ignore_internal=settings.ignore_internal_src,
        min_severity=settings.min_alert_severity,
    )
    geoip = GeoIPResolver(settings.geoip_db_path, settings.geoip_online_fallback)
    pipeline = IngestPipeline(storage, loader, engine, aggregator, geoip)

    state.storage = storage
    state.loader = loader
    state.engine = engine
    state.aggregator = aggregator
    state.geoip = geoip
    state.pipeline = pipeline

    task = asyncio.create_task(_maintenance_loop())
    logger.info(
        "Mini SIEM 后端启动完成，规则 %s 条，存储后端 %s",
        len(engine.rules),
        settings.storage_backend,
    )

    yield

    task.cancel()
    await geoip.close()
    await storage.close()
    logger.info("Mini SIEM 后端已关闭")


app = FastAPI(
    title="Mini SIEM",
    description="迷你 SIEM / 日志威胁检测平台：日志采集、规则检测、告警聚合与攻击地图",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_PREFIX = "/api/v1"
for module in (ingest, logs, alerts, rules, stats):
    app.include_router(module.router, prefix=API_PREFIX)


@app.get(f"{API_PREFIX}/health", tags=["系统"], summary="健康检查")
async def health() -> dict[str, object]:
    """返回服务与存储后端的健康状态。"""
    storage_ok = await state.storage.ping() if state.storage else False
    return {
        "status": "ok" if storage_ok else "degraded",
        "version": __version__,
        "backend": settings.storage_backend,
        "storage": storage_ok,
        "rules_loaded": len(state.loader.rules) if state.loader else 0,
        "rules_enabled": len(state.engine.rules) if state.engine else 0,
    }


# ---------------- 前端静态资源托管 ----------------
# 配置 FRONTEND_DIST 且目录存在时，由后端直接托管前端构建产物，可省掉 nginx 容器
_static_dir = Path(settings.frontend_dist) if settings.frontend_dist else None
if _static_dir and _static_dir.is_dir():
    _assets_dir = _static_dir / "assets"
    if _assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=_assets_dir), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str) -> FileResponse:
        """SPA 前端回退：命中真实静态文件则返回该文件，否则统一返回 index.html。"""
        target = _static_dir / full_path
        if full_path and target.is_file():
            return FileResponse(target)
        return FileResponse(_static_dir / "index.html")

    logger.info("已启用前端静态资源托管：%s", _static_dir)

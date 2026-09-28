"""FastAPI 应用入口：初始化组件、注册路由、启动后台维护任务。"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("mini-siem")

MAINTENANCE_INTERVAL = 60
_cleanup_counter = 0


async def _maintenance_loop() -> None:
    """后台维护任务：等待 ES 就绪、初始化索引、热加载规则、定期清理数据。"""
    global _cleanup_counter
    es_ready = False
    while True:
        try:
            if not es_ready:
                es_ready = await state.storage.ping()
                if not es_ready:
                    logger.warning("Elasticsearch 未就绪，%s 秒后重试", MAINTENANCE_INTERVAL)
                else:
                    await state.storage.ensure_indices()
                    logger.info("Elasticsearch 连接成功，索引已就绪")

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
            es_ready = False
        await asyncio.sleep(MAINTENANCE_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理：启动时装配组件，关闭时释放资源。"""
    storage = ESStorage(settings.es_url, settings.es_index_prefix, settings.es_retention_days)
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
    logger.info("Mini SIEM 后端启动完成，规则 %s 条，ES 地址 %s", len(engine.rules), settings.es_url)

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
    """返回服务与 Elasticsearch 的健康状态。"""
    es_ok = await state.storage.ping() if state.storage else False
    return {
        "status": "ok" if es_ok else "degraded",
        "version": __version__,
        "elasticsearch": es_ok,
        "rules_loaded": len(state.loader.rules) if state.loader else 0,
        "rules_enabled": len(state.engine.rules) if state.engine else 0,
    }

"""应用全局状态容器：集中持有存储、规则引擎等单例对象。"""
from __future__ import annotations

from app.engine.aggregator import AlertAggregator
from app.engine.geoip import GeoIPResolver
from app.engine.matcher import RuleEngine
from app.engine.pipeline import IngestPipeline
from app.engine.rule_loader import RuleLoader
from app.storage.es_client import ESStorage


class AppState:
    """保存全局单例组件，供 API 依赖注入使用。"""

    storage: ESStorage | None = None
    loader: RuleLoader | None = None
    engine: RuleEngine | None = None
    aggregator: AlertAggregator | None = None
    geoip: GeoIPResolver | None = None
    pipeline: IngestPipeline | None = None

    @property
    def ready(self) -> bool:
        """判断各组件是否已初始化完成。"""
        return self.pipeline is not None and self.storage is not None


state = AppState()

"""GeoIP 解析模块：为攻击源 IP 补充地理坐标，用于攻击地图。

优先级：本地 MaxMind mmdb 文件 > 在线免费接口(ip-api.com) > 不解析。
在线查询结果会写入内存缓存，避免重复请求并规避接口频率限制。
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

import httpx

from app.models.schemas import GeoInfo
from app.utils.net import is_internal_ip, is_valid_ip

logger = logging.getLogger(__name__)

ONLINE_API = "http://ip-api.com/json/{ip}"
# 免费接口限制 45 次/分钟，这里做简单节流
MIN_INTERVAL = 1.4


class GeoIPResolver:
    """IP 地理位置解析器（支持离线 mmdb 与在线降级）。"""

    def __init__(self, db_path: str = "", online_fallback: bool = True) -> None:
        """加载 mmdb 数据库（如存在），并初始化缓存。"""
        self.online_fallback = online_fallback
        self._reader = None
        self._cache: dict[str, GeoInfo | None] = {}
        self._last_request = 0.0
        self._client: httpx.AsyncClient | None = None

        if db_path and Path(db_path).exists():
            try:
                import geoip2.database  # 延迟导入，未安装依赖时不影响服务启动

                self._reader = geoip2.database.Reader(db_path)
                logger.info("GeoIP 离线库加载成功: %s", db_path)
            except Exception as exc:  # noqa: BLE001 - 缺少依赖或库损坏时降级
                logger.warning("GeoIP 离线库加载失败(%s)，将使用在线解析: %s", db_path, exc)
        elif db_path:
            logger.warning("GeoIP 数据库文件不存在: %s", db_path)

    async def close(self) -> None:
        """释放资源。"""
        if self._client:
            await self._client.aclose()
        if self._reader:
            self._reader.close()

    async def resolve(self, ip: str | None) -> GeoInfo | None:
        """解析 IP 归属地，内网/非法 IP 直接返回 None。"""
        if not ip or not is_valid_ip(ip) or is_internal_ip(ip):
            return None
        if ip in self._cache:
            return self._cache[ip]

        geo = self._resolve_offline(ip)
        if geo is None and self.online_fallback:
            geo = await self._resolve_online(ip)
        self._cache[ip] = geo
        if len(self._cache) > 5000:  # 简单容量控制
            self._cache.clear()
        return geo

    def _resolve_offline(self, ip: str) -> GeoInfo | None:
        """使用本地 mmdb 查询城市级位置。"""
        if not self._reader:
            return None
        try:
            resp = self._reader.city(ip)
        except Exception:  # 地址未收录时返回 None
            return None
        if resp.location.latitude is None:
            return None
        return GeoInfo(
            country=resp.country.name or resp.registered_country.name,
            country_code=resp.country.iso_code,
            city=resp.city.name,
            lat=resp.location.latitude,
            lon=resp.location.longitude,
        )

    async def _resolve_online(self, ip: str) -> GeoInfo | None:
        """调用在线免费接口解析（带节流）。"""
        elapsed = time.monotonic() - self._last_request
        if elapsed < MIN_INTERVAL:
            return None
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=5)
        self._last_request = time.monotonic()
        try:
            resp = await self._client.get(
                ONLINE_API.format(ip=ip),
                params={"fields": "status,country,countryCode,city,lat,lon", "lang": "zh-CN"},
            )
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("在线 GeoIP 查询失败 %s: %s", ip, exc)
            return None
        if data.get("status") != "success":
            return None
        return GeoInfo(
            country=data.get("country"),
            country_code=data.get("countryCode"),
            city=data.get("city"),
            lat=data.get("lat"),
            lon=data.get("lon"),
        )

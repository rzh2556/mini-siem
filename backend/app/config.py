"""全局配置模块：从环境变量 / .env 加载运行参数。"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """应用配置项，字段名不区分大小写，与 .env 中的键一一对应。"""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ---------- 存储后端 ----------
    # sqlite（默认，零依赖、低负载）/ elasticsearch（功能全但吃内存）
    storage_backend: str = "sqlite"
    sqlite_path: str = "data/siem.db"

    # ---------- Elasticsearch ----------
    es_url: str = "http://localhost:9200"
    es_index_prefix: str = "siem"
    # 日志保留天数：SQLite 后端同样使用该值清理过期日志
    es_retention_days: int = 30

    # ---------- 前端静态资源 ----------
    # 非空且目录存在时，由后端直接托管前端构建产物（可省掉 nginx 容器）
    frontend_dist: str = ""

    # ---------- 管理后台账号与登录 ----------
    # 首次启动时创建的管理员账号；初始密码取 admin_password，未配置时默认 admin123（首次登录强制修改）
    admin_username: str = "admin"
    admin_password: str = ""
    # JWT 签名密钥：留空则在首次启动时随机生成并持久化到系统库
    jwt_secret: str = ""
    # 登录令牌有效期（小时）
    token_expire_hours: int = 12
    # 账号密码等系统数据使用的独立 SQLite 库（与日志存储后端无关）
    system_db_path: str = "data/system.db"

    # ---------- 服务 ----------
    agent_token: str = "change-me-agent-token"
    api_token: str = ""
    log_level: str = "INFO"
    cors_origins: str = "*"

    # ---------- GeoIP ----------
    geoip_db_path: str = ""
    geoip_online_fallback: bool = True
    # 离线库加载成功时是否跳过在线解析（避免上传日志时逐个 IP 联网导致卡顿）
    geoip_offline_only: bool = False

    # ---------- 规则 ----------
    rules_dir: str = "rules"
    rules_reload_interval: int = 60

    # ---------- 文件上传 ----------
    # 单文件上传大小上限（MB）；Windows .evtx 安全日志通常较大，默认放宽到 200MB
    max_upload_mb: int = 200
    # 单文件最多解析的日志行/事件条数，防止超大文件拖垮服务
    max_upload_lines: int = 200_000

    # ---------- 告警降噪 ----------
    alert_cooldown: int = 300
    min_alert_severity: str = "low"
    ip_whitelist: str = "127.0.0.1,::1"
    ignore_internal_src: bool = False

    @property
    def cors_origin_list(self) -> list[str]:
        """把逗号分隔的 CORS 配置转成列表。"""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def whitelist_ips(self) -> set[str]:
        """把逗号分隔的 IP 白名单转成集合。"""
        return {ip.strip() for ip in self.ip_whitelist.split(",") if ip.strip()}

    @property
    def log_index_pattern(self) -> str:
        """日志索引通配模式。"""
        return f"{self.es_index_prefix}-logs-*"

    @property
    def alert_index(self) -> str:
        """告警索引名。"""
        return f"{self.es_index_prefix}-alerts"


@lru_cache
def get_settings() -> Settings:
    """返回全局唯一的配置实例（带缓存）。"""
    return Settings()


settings = get_settings()

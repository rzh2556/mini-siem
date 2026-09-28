"""系统存储：管理员账号密码、JWT 密钥、运行参数覆盖值。

与业务存储后端（SQLite/ES）无关，始终使用一个独立的小 SQLite 文件，
保证即便业务库换成 Elasticsearch，账号体系也不受影响。
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt

from app.config import settings

logger = logging.getLogger(__name__)

# PBKDF2 迭代次数：兼顾安全性与 1~2G 小服务器的 CPU 开销
PBKDF2_ITERATIONS = 200_000

# 允许在后台修改并热生效的配置项白名单（键名与 app.config.Settings 字段一致）
# 值同时用于：启动时覆盖 settings、后台保存时类型校验
EDITABLE_SETTINGS: dict[str, type] = {
    "es_retention_days": int,
    "alert_cooldown": int,
    "min_alert_severity": str,
    "ip_whitelist": str,
    "ignore_internal_src": bool,
    "geoip_online_fallback": bool,
    "geoip_db_path": str,
    "log_level": str,
    "cors_origins": str,
    "api_token": str,
    "agent_token": str,
    "rules_reload_interval": int,
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    must_change   INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def hash_password(password: str) -> str:
    """使用 PBKDF2-SHA256 对密码加盐哈希，返回可直接落库的字符串。"""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    """校验明文密码与落库哈希是否匹配，格式非法时直接返回 False。"""
    try:
        algorithm, iterations_text, salt, expected = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations_text)
        ).hex()
        return secrets.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


class SystemStore:
    """系统库访问层：账号、键值配置的读写（线程安全的单连接）。"""

    def __init__(self, path: str) -> None:
        """打开（必要时创建）系统库并初始化表结构。"""
        self.path = Path(path)
        if str(self.path.parent) not in ("", "."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)
            self._conn.commit()

    def close(self) -> None:
        """关闭数据库连接。"""
        with self._lock:
            self._conn.close()

    # ---------------- 管理员账号 ----------------

    def ensure_admin(self, username: str, password: str, must_change: bool) -> bool:
        """首次启动时创建管理员账号；账号已存在则不处理。返回是否为本次新建。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT username FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row:
                return False
            self._conn.execute(
                "INSERT INTO users (username, password_hash, must_change, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    username,
                    hash_password(password),
                    1 if must_change else 0,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()
            logger.info("已创建管理员账号：%s（%s）", username, "需尽快修改默认密码" if must_change else "使用环境变量密码")
            return True

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        """校验账号密码，成功返回用户信息字典，失败返回 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT username, password_hash, must_change FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            return None
        return {"username": row["username"], "must_change": bool(row["must_change"])}

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """凭旧密码修改密码，成功后清除“必须改密”标记。旧密码错误返回 False。"""
        user = self.authenticate(username, old_password)
        if not user:
            return False
        return self.set_password(username, new_password, must_change=False)

    def set_password(self, username: str, new_password: str, must_change: bool) -> bool:
        """直接重置指定账号密码（供命令行重置工具使用，不校验旧密码）。"""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE users SET password_hash = ?, must_change = ? WHERE username = ?",
                (hash_password(new_password), 1 if must_change else 0, username),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    # ---------------- JWT 密钥 ----------------

    def get_jwt_secret(self) -> str:
        """读取 JWT 签名密钥；不存在则随机生成一个并持久化。"""
        secret = self.get_value("jwt_secret")
        if isinstance(secret, str) and secret:
            return secret
        secret = secrets.token_urlsafe(48)
        self.set_value("jwt_secret", secret)
        return secret

    # ---------------- 登录令牌 ----------------

    def issue_token(self, username: str) -> tuple[str, datetime]:
        """为登录成功的管理员签发 JWT，返回 (令牌, 过期时间)。"""
        secret = settings.jwt_secret or self.get_jwt_secret()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.token_expire_hours)
        payload = {"sub": username, "exp": expires_at, "iat": datetime.now(timezone.utc)}
        return jwt.encode(payload, secret, algorithm="HS256"), expires_at

    def verify_token(self, token: str) -> str | None:
        """校验 JWT 并返回用户名；任何异常（过期/伪造/解析失败）都返回 None。"""
        try:
            secret = settings.jwt_secret or self.get_jwt_secret()
            payload = jwt.decode(token, secret, algorithms=["HS256"])
        except jwt.PyJWTError:
            return None
        username = payload.get("sub")
        return username if isinstance(username, str) else None

    # ---------------- 键值配置 ----------------

    def get_value(self, key: str, default: Any = None) -> Any:
        """读取一个 JSON 编码的配置值，缺失时返回默认值。"""
        with self._lock:
            row = self._conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def set_value(self, key: str, value: Any) -> None:
        """写入一个 JSON 编码的配置值。"""
        with self._lock:
            self._conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value, ensure_ascii=False)),
            )
            self._conn.commit()

    def get_settings_overrides(self) -> dict[str, Any]:
        """读取全部受管理的运行参数覆盖值（自动忽略白名单之外的脏数据）。"""
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM kv").fetchall()
        result: dict[str, Any] = {}
        for row in rows:
            if row["key"] in EDITABLE_SETTINGS:
                try:
                    result[row["key"]] = json.loads(row["value"])
                except json.JSONDecodeError:
                    continue
        return result

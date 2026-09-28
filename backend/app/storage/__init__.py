"""存储层包初始化：提供 Elasticsearch 与 SQLite 两种可互换的存储后端。"""
from app.storage.es_client import ESStorage
from app.storage.sqlite_client import SQLiteStorage

# 存储后端联合类型，供管道、聚合器与 API 层做类型标注
StorageBackend = ESStorage | SQLiteStorage

__all__ = ["ESStorage", "SQLiteStorage", "StorageBackend"]

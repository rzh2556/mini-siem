"""把后台保存的运行参数同步回写 .env 文件。

后台配置本身持久化在 data/system.db 的 kv 表中（服务启动时覆盖环境变量生效），
这里额外把改动同步写回 .env，方便用户直接在文件中查看与备份。
只在 .env 已存在且可写时回写（Docker 等场景自动跳过），失败也不影响主流程。
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def default_env_path() -> Path:
    """返回默认的 .env 路径：本文件位于 backend/app/system/ 下，向上三级即项目根目录。"""
    return Path(__file__).resolve().parents[3] / ".env"


def _format_value(value: object) -> str:
    """把 Python 值转成 .env 中的文本形式（布尔转 true/false，换行转空格）。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).replace("\r", " ").replace("\n", " ")


def update_env_file(path: Path, updates: dict[str, object]) -> bool:
    """把 updates 中的键值写回 .env，保留注释与原有行，仅替换对应 key 的值行。

    键名统一转大写匹配（与 .env 约定一致）；文件不存在时直接跳过，不新建。
    返回是否写入成功。
    """
    if not updates:
        return True
    if not path.exists():
        logger.info("未找到 .env(%s)，本次仅保存到系统库", path)
        return False

    upper = {key.upper(): _format_value(value) for key, value in updates.items()}
    try:
        original = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("读取 .env 失败(%s)，跳过回写: %s", path, exc)
        return False

    handled: set[str] = set()
    result: list[str] = []
    for line in original:
        stripped = line.strip()
        # 注释、空行以及非 KEY=VALUE 形式原样保留
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            result.append(line)
            continue
        key = stripped.split("=", 1)[0].strip().upper()
        if key in upper and key not in handled:
            result.append(f"{key}={upper[key]}")
            handled.add(key)
        else:
            result.append(line)

    # .env 中原本没有的键，追加到文件末尾
    missing = [key for key in upper if key not in handled]
    if missing:
        if result and result[-1].strip():
            result.append("")
        result.append("# ---- 由后台同步写入 ----")
        result.extend(f"{key}={upper[key]}" for key in missing)

    # 原子写入：先写临时文件再替换，避免中途失败损坏 .env
    try:
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text("\n".join(result) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        logger.warning("写入 .env 失败(%s)，配置仍已保存到系统库: %s", path, exc)
        return False
    logger.info("运行参数已同步回写 .env: %s（%d 项）", path, len(upper))
    return True

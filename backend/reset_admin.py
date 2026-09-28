"""管理员密码重置工具（忘记密码时使用）。

用法（在安装目录的 backend 下，使用服务自带虚拟环境）：
    ../venv/bin/python reset_admin.py                 # 随机生成一个新密码并打印
    ../venv/bin/python reset_admin.py 新密码          # 直接指定新密码（至少 8 位）

开发环境（项目 backend 目录）：
    python reset_admin.py

重置后该账号恢复为“无需强制改密”状态，可用新密码直接登录。
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path


def load_env_file() -> None:
    """读取部署目录中的 .env 注入环境变量（已存在的环境变量优先，不覆盖）。

    systemd 通过 EnvironmentFile 加载 .env；手动运行本脚本时没有该机制，
    因此自行做最小解析，保证能定位到 SYSTEM_DB_PATH / ADMIN_USERNAME。
    """
    for candidate in (Path.cwd().parent / ".env", Path.cwd() / ".env"):
        if not candidate.exists():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
        break


def main() -> int:
    """执行密码重置，成功返回 0、失败返回 1。"""
    load_env_file()

    # 延迟导入：确保环境变量已就位
    from app.config import settings
    from app.system import SystemStore

    new_password = sys.argv[1] if len(sys.argv) > 1 else f"Ms-{secrets.token_urlsafe(10)}"
    if len(new_password) < 8:
        print("[错误] 新密码至少需要 8 位")
        return 1

    print(f"[信息] 系统库路径：{settings.system_db_path}")
    store = SystemStore(settings.system_db_path)
    try:
        if not store.set_password(settings.admin_username, new_password, must_change=False):
            print(f"[错误] 账号 {settings.admin_username} 不存在，"
                  f"请先正常启动一次服务完成初始化")
            return 1
    finally:
        store.close()

    print(f"[成功] 管理员 {settings.admin_username} 的密码已重置")
    print(f"[新密码] {new_password}")
    if len(sys.argv) == 1:
        print("[提示] 该密码为随机生成，请妥善保存，登录后可在后台再次修改")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env bash
# ============================================================
# Mini SIEM 裸机一键部署脚本（SQLite + 单进程，低负载方案）
#
# 特点：不依赖 Docker / Elasticsearch，内存占用通常在 100~200MB，
#       适合 1~2GB 内存的小型服务器。后端同时托管前端静态文件，
#       因此也不需要额外装 nginx。
#
# 支持系统：Alibaba Cloud Linux / CentOS / RHEL / Anolis（dnf/yum）
#           Ubuntu / Debian（apt）
#
# 用法（在仓库根目录执行）：
#   sudo bash deploy/install.sh
#   INSTALL_DIR=/srv/mini-siem sudo -E bash deploy/install.sh
#
# 可覆盖的环境变量：
#   INSTALL_DIR   安装目录，默认 /opt/mini-siem
#   SERVICE_PORT  监听端口，默认 8000
#   AGENT_TOKEN   采集令牌，默认随机生成
#   PYPI_MIRROR   pip 源，默认清华镜像（国内服务器下载快很多）
# ============================================================
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/mini-siem}"
SERVICE_PORT="${SERVICE_PORT:-8000}"
PYPI_MIRROR="${PYPI_MIRROR:-https://pypi.tuna.tsinghua.edu.cn/simple}"
SERVICE_USER="minisiem"

# 脚本所在目录的上一级就是仓库根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

log() { echo -e "\033[32m[mini-siem]\033[0m $*"; }
warn() { echo -e "\033[33m[mini-siem]\033[0m $*"; }
die() { echo -e "\033[31m[mini-siem] 错误：$*\033[0m" >&2; exit 1; }

# 检查是否以 root 运行（安装系统包、写 systemd 单元都需要）
require_root() {
    [ "$(id -u)" -eq 0 ] || die "请使用 root 或 sudo 运行本脚本"
}

# 安装系统依赖：python3 运行环境与 curl（健康检查用）
install_packages() {
    log "安装系统依赖（python3 / venv / curl）..."
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y python3 python3-venv python3-pip curl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 python3-pip curl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 python3-pip curl
    else
        die "未识别的包管理器，请手动安装 python3(含 venv) 与 curl"
    fi
}

# 创建专用系统用户（不可登录），避免以 root 身份对外提供服务
ensure_user() {
    if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
        log "创建系统用户 ${SERVICE_USER} ..."
        useradd --system --shell /sbin/nologin --home-dir "${INSTALL_DIR}" "${SERVICE_USER}" 2>/dev/null \
            || useradd --system --shell /usr/sbin/nologin --home-dir "${INSTALL_DIR}" "${SERVICE_USER}"
    fi
}

# 同步后端代码与检测规则到安装目录
sync_backend() {
    log "复制后端代码与规则到 ${INSTALL_DIR} ..."
    mkdir -p "${INSTALL_DIR}"/{backend,rules,data,frontend,geoip}
    cp -a "${SRC_DIR}/backend/app" "${INSTALL_DIR}/backend/"
    cp -a "${SRC_DIR}/backend/requirements.txt" "${INSTALL_DIR}/backend/"
    cp -a "${SRC_DIR}/backend/rules/." "${INSTALL_DIR}/rules/"
}

# 处理前端产物：优先使用已构建的 dist，缺失时尝试本地 npm 构建
prepare_frontend() {
    if [ -f "${SRC_DIR}/frontend/dist/index.html" ]; then
        log "检测到前端构建产物，直接复用"
        rm -rf "${INSTALL_DIR}/frontend/dist"
        cp -a "${SRC_DIR}/frontend/dist" "${INSTALL_DIR}/frontend/dist"
        return
    fi

    if command -v npm >/dev/null 2>&1; then
        warn "未找到 frontend/dist，尝试在服务器上构建前端（较慢且吃内存）..."
        ( cd "${SRC_DIR}/frontend" && npm ci && npm run build )
        rm -rf "${INSTALL_DIR}/frontend/dist"
        cp -a "${SRC_DIR}/frontend/dist" "${INSTALL_DIR}/frontend/dist"
        return
    fi

    die "未找到 ${SRC_DIR}/frontend/dist，且服务器上没有 npm。
     推荐做法：在本机 frontend 目录执行 npm run build，
     再把 frontend/dist 上传到服务器的 ${SRC_DIR}/frontend/ 后重跑本脚本。"
}

# 挑选一个 >=3.8 的 Python 解释器（FastAPI/Pydantic 2 的最低要求）
find_python() {
    local candidate
    for candidate in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
        if command -v "${candidate}" >/dev/null 2>&1 \
            && "${candidate}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
            echo "${candidate}"
            return 0
        fi
    done
    return 1
}

# 创建 Python 虚拟环境并安装依赖
setup_venv() {
    local python_bin
    python_bin="$(find_python)" || die "未找到 Python 3.8+，请先安装（如 dnf install -y python3.11）后重试"
    log "使用 ${python_bin} 创建虚拟环境（pip 源：${PYPI_MIRROR}）..."

    "${python_bin}" -m venv "${INSTALL_DIR}/venv"

    # RHEL/CentOS 系默认移除了 ensurepip，venv 里可能没有 pip，用官方脚本补齐
    if ! "${INSTALL_DIR}/venv/bin/python" -m pip --version >/dev/null 2>&1; then
        log "虚拟环境缺少 pip，正在引导安装 ..."
        curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
        "${INSTALL_DIR}/venv/bin/python" /tmp/get-pip.py -i "${PYPI_MIRROR}"
        rm -f /tmp/get-pip.py
    fi

    "${INSTALL_DIR}/venv/bin/pip" install --upgrade pip -i "${PYPI_MIRROR}"
    "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/backend/requirements.txt" -i "${PYPI_MIRROR}"
}

# 生成 .env（已存在则保留，避免覆盖用户改动）
write_env() {
    if [ -f "${INSTALL_DIR}/.env" ]; then
        log "已存在 ${INSTALL_DIR}/.env，保留原有配置"
        return
    fi

    local token="${AGENT_TOKEN:-}"
    if [ -z "${token}" ]; then
        token="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi

    log "生成配置文件 ${INSTALL_DIR}/.env ..."
    cat > "${INSTALL_DIR}/.env" <<EOF
# ===== Mini SIEM 低负载（SQLite 单进程）配置 =====

# ---- 存储后端：sqlite 零依赖；elasticsearch 需另装 ES ----
STORAGE_BACKEND=sqlite
SQLITE_PATH=${INSTALL_DIR}/data/siem.db
ES_RETENTION_DAYS=30

# ---- 规则目录 ----
RULES_DIR=${INSTALL_DIR}/rules
RULES_RELOAD_INTERVAL=60

# ---- 由后端托管前端静态文件（免装 nginx）----
FRONTEND_DIST=${INSTALL_DIR}/frontend/dist

# ---- 采集鉴权（务必修改）----
AGENT_TOKEN=${token}
API_TOKEN=

# ---- GeoIP（有 mmdb 就填绝对路径，留空则跳过离线解析）----
GEOIP_DB_PATH=
GEOIP_ONLINE_FALLBACK=true

# ---- 告警降噪 ----
ALERT_COOLDOWN=300
MIN_ALERT_SEVERITY=low
IP_WHITELIST=127.0.0.1,::1
IGNORE_INTERNAL_SRC=false

# ---- 其他 ----
LOG_LEVEL=INFO
CORS_ORIGINS=*
EOF
}

# 安装并启动 systemd 服务
install_service() {
    log "安装 systemd 服务 ..."
    sed -e "s#/opt/mini-siem#${INSTALL_DIR}#g" \
        "${SCRIPT_DIR}/mini-siem.service" > /etc/systemd/system/mini-siem.service
    sed -i "s#--port 8000#--port ${SERVICE_PORT}#" /etc/systemd/system/mini-siem.service

    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
    systemctl daemon-reload
    systemctl enable mini-siem >/dev/null 2>&1
    systemctl restart mini-siem
}

# 轮询健康检查接口，确认服务真的起来了
wait_healthy() {
    log "等待服务就绪 ..."
    for _ in $(seq 1 30); do
        if curl -fsS "http://127.0.0.1:${SERVICE_PORT}/api/v1/health" >/dev/null 2>&1; then
            curl -s "http://127.0.0.1:${SERVICE_PORT}/api/v1/health"
            echo
            return 0
        fi
        sleep 1
    done
    warn "健康检查超时，请执行 journalctl -u mini-siem -n 50 查看日志"
    return 1
}

main() {
    require_root
    [ -d "${SRC_DIR}/backend/app" ] || die "未找到 ${SRC_DIR}/backend/app，请在仓库根目录执行本脚本"

    install_packages
    ensure_user
    sync_backend
    prepare_frontend
    setup_venv
    write_env
    install_service
    wait_healthy

    log "部署完成！"
    echo "  访问地址 ： http://<服务器IP>:${SERVICE_PORT}/"
    echo "  采集令牌 ： 见 ${INSTALL_DIR}/.env 中的 AGENT_TOKEN"
    echo "  查看状态 ： systemctl status mini-siem"
    echo "  查看日志 ： journalctl -u mini-siem -f"
    echo "  修改配置 ： 编辑 ${INSTALL_DIR}/.env 后执行 systemctl restart mini-siem"
    echo
    warn "如服务器有安全组/防火墙，请放行 TCP ${SERVICE_PORT} 端口"
}

main "$@"

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai

WORKDIR /app

# 说明：这里不再通过 apt 安装 curl/tzdata，让镜像构建只依赖 pip 源，
# 避免国内服务器因 deb.debian.org 无法解析（DNS 不通）导致构建直接失败。
# 容器内的时区由 requirements.txt 中的 tzdata 包（Python zoneinfo）提供，
# 健康检查改用 Python 发起请求，因此不再需要 curl。
COPY requirements.txt .
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

COPY app ./app
COPY rules ./rules

EXPOSE 8000

# 健康检查：请求 /api/v1/health，返回 200 视为健康
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import sys,urllib.request;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health',timeout=3).getcode()==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

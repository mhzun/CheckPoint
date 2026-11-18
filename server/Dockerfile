# CheckPoint 验证服务镜像（安全加固版 v1.3.0）
FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DB_PATH=/data/checkpoint.db

# 非 root 运行用户（固定 UID 10001，便于宿主机 bind mount 权限对齐）
RUN useradd -r -u 10001 -M -s /usr/sbin/nologin appuser

WORKDIR /app

# 依赖层单独缓存，改代码不会重装依赖
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY main.py ./main.py
COPY test_api.py ./test_api.py
COPY scripts/ ./scripts/
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

# 数据目录（compose 会把 ./data 挂载到这里；宿主机需 chown 10001:10001 ./data）
# 证书目录（compose 可选挂载 ./certs -> /certs:ro；有证书即自动启用 HTTPS）
RUN mkdir -p /data /certs && chown -R appuser:appuser /app /data /certs

USER appuser

EXPOSE 8000

# 健康检查改为 TCP 探活 + 宽容重试：
# 攻击者用大量半开连接打满 --limit-concurrency 时，/health 的 JSON 探针会被连坐 503，
# 导致 Docker 误判 unhealthy 触发重启风暴（v1.2.0 攻防演练发现 V28）。
# TCP 探活只需接受连接（listen 队列），配合 retries=5 大幅提高鲁棒性。
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
    CMD python -c "import socket; socket.create_connection(('127.0.0.1', 8000), timeout=3).close()"

ENTRYPOINT ["/app/entrypoint.sh"]

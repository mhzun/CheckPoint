#!/bin/sh
# CheckPoint v1.2.0 容器入口：
# 1) 收紧数据文件权限（UMASK 已在应用内设置，这里兜底处理既有文件）
# 2) 检测 /certs 下是否存在证书：有则启用 HTTPS，无则保持 HTTP（本地开发）
# 3) --no-proxy-headers：彻底关闭 uvicorn 层的 X-Forwarded-For 处理，
#    避免其默认行为（forwarded-allow-ips=127.0.0.1）用攻击者可伪造的
#    XFF 第一个条目重写 client IP，架空应用层 TRUST_PROXY（v1.2.0 修复 V26）
set -e

chmod 600 /data/*.db /data/*.db-wal /data/*.db-shm 2>/dev/null || true

ARGS="--host 0.0.0.0 --port 8000 \
 --limit-concurrency 200 \
 --no-proxy-headers \
 --h11-max-incomplete-event-size 8192 \
 --no-server-header"

if [ -f /certs/cert.pem ] && [ -f /certs/key.pem ]; then
    ARGS="$ARGS --ssl-certfile /certs/cert.pem --ssl-keyfile /certs/key.pem"
    echo "[entrypoint] TLS enabled (/certs/cert.pem)"
else
    echo "[entrypoint] TLS certs not found, running plain HTTP (dev only)"
fi

exec python -m uvicorn main:app $ARGS

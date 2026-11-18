#!/bin/bash
# 巡检（root cron 每 5 分钟）：服务健康 + 容器状态 + 磁盘 + 审计日志异常计数
# 建议 crontab: */5 * * * * /opt/checkpoint/ops/healthcheck-cron.sh
cd /opt/checkpoint || exit 1
LOG=/opt/checkpoint/logs/ops.log
mkdir -p /opt/checkpoint/logs
NOW=$(date '+%F %T')

HEALTH=$(curl -sk -m 5 https://127.0.0.1:8080/health 2>/dev/null)
if echo "$HEALTH" | grep -q '"code":0'; then
  echo "$NOW health=OK" >> "$LOG"
else
  echo "$NOW health=FAIL body=$HEALTH" >> "$LOG"
fi

STATE=$(docker inspect checkpoint-auth --format '{{.State.Status}} {{.State.Health.Status}}' 2>/dev/null)
echo "$NOW container=$STATE" >> "$LOG"
[ "${STATE%% *}" = "running" ] || echo "$NOW ALERT container not running" >> "$LOG"

DISK=$(df -h /opt/checkpoint | awk 'NR==2 {print $5}')
echo "$NOW disk_use=$DISK" >> "$LOG"
echo "$DISK" | sed 's/%//' | awk '{if ($1+0 >= 85) exit 1}' || echo "$NOW ALERT disk >= 85%" >> "$LOG"

# 审计日志近 5 分钟的管理员鉴权失败次数（粗粒度告警）
AUDIT=/opt/checkpoint/data/audit.jsonl
if [ -f "$AUDIT" ]; then
  FAILS=$(tail -200 "$AUDIT" 2>/dev/null | grep -c '"admin_auth_failed"')
  [ "$FAILS" -gt 0 ] && echo "$NOW note admin_auth_failed_recent=$FAILS" >> "$LOG"
fi

# 日志滚动（保留 30 天）
find /opt/checkpoint/logs -name '*.log' -size +20M -exec mv {} {}.old \; 2>/dev/null
find /opt/checkpoint/logs -name '*.log.*' -mtime +30 -delete 2>/dev/null
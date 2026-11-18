#!/bin/bash
# 每日备份（root cron 调用）：容器内 sqlite3 在线备份 + 完整性校验 + 保留 14 份
# 建议 crontab: 15 3 * * * /opt/checkpoint/ops/backup-cron.sh
cd /opt/checkpoint || exit 1
LOG="/opt/checkpoint/logs/backup.log"
mkdir -p /opt/checkpoint/logs
echo "$(date '+%F %T') backup start" >> "$LOG"
docker compose exec -T checkpoint-auth python scripts/backup.py >> "$LOG" 2>&1
echo "$(date '+%F %T') backup done rc=$?" >> "$LOG"
# 备份目录也做个异机拷贝位（示例：挂载的共享目录/rsync 目标），生产按需启用：
# rsync -a --delete /opt/checkpoint/data/backups/ /mnt/backup-nas/checkpoint/ >> "$LOG" 2>&1
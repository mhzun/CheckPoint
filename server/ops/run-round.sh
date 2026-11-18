#!/bin/bash
# CheckPoint v1.3.0 全量测试轮次执行器（隔离测试容器，不接触生产数据）
# 用法: ./run-round.sh <轮次号>
# 每轮：重建测试容器（临时 DB 清空）→ 依次跑 8 个阶段（阶段间 restart 重置限流桶）→ 汇总
cd /opt/checkpoint || exit 1

ROUND="${1:-0}"
OUT="/opt/checkpoint/test-results/round-$ROUND"
mkdir -p "$OUT"
LOG="$OUT/round.log"
echo "=== ROUND $ROUND start $(date '+%F %T') ===" | tee -a "$LOG"

COMPOSE="docker compose -f docker-compose.test.yml"

wait_healthy() {
  for i in $(seq 1 60); do
    if $COMPOSE exec -T checkpoint-test \
        python -c "import socket; socket.create_connection(('127.0.0.1',8000),3).close()" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

fresh_env() {
  echo "--- recreate test container (fresh DB) ---" | tee -a "$LOG"
  $COMPOSE down > /dev/null 2>&1
  $COMPOSE up -d --force-recreate > /dev/null 2>&1
  if wait_healthy; then
    echo "--- test env healthy ---" | tee -a "$LOG"
  else
    echo "--- TEST ENV UNHEALTHY ---" | tee -a "$LOG"
    exit 2
  fi
}

restart_env() {
  echo "--- restart test container ---" | tee -a "$LOG"
  $COMPOSE restart > /dev/null 2>&1
  if wait_healthy; then
    echo "--- test env healthy ---" | tee -a "$LOG"
  else
    echo "--- TEST ENV UNHEALTHY after restart ---" | tee -a "$LOG"
    exit 2
  fi
}

run_stage() {
  local stage="$1"
  echo "--- stage $stage start $(date '+%F %T') ---" | tee -a "$LOG"
  if $COMPOSE exec -T -e BASE_URL=https://127.0.0.1:8000 checkpoint-test \
      python test_api.py "$stage" > "$OUT/$stage.log" 2>&1; then
    echo "--- stage $stage PASS ---" | tee -a "$LOG"
    grep -E "^结果：" "$OUT/$stage.log" | tee -a "$LOG"
  else
    echo "--- stage $stage FAIL ---" | tee -a "$LOG"
    grep -E "^结果：" "$OUT/$stage.log" | tee -a "$LOG"
    grep -E "^\s+\[FAIL\]" "$OUT/$stage.log" | head -20 | tee -a "$LOG"
    echo "ROUND $ROUND STAGE $stage FAILED" >> "$OUT/FAILED"
  fi
}

fresh_env
run_stage func
restart_env; run_stage escape
restart_env; run_stage race
restart_env; run_stage sig
restart_env; run_stage security
restart_env; run_stage rebind
restart_env; run_stage spoof
restart_env; run_stage mc
restart_env; run_stage ip

# 汇总（只统计各阶段日志，避免 round.log 重复计数）
TOTAL_PASS=0; TOTAL_FAIL=0
for s in func escape race sig security rebind spoof mc ip; do
  P=$(grep -oE "PASS=[0-9]+" "$OUT/$s.log" 2>/dev/null | head -1 | grep -oE "[0-9]+")
  F=$(grep -oE "FAIL=[0-9]+" "$OUT/$s.log" 2>/dev/null | head -1 | grep -oE "[0-9]+")
  TOTAL_PASS=$((TOTAL_PASS + ${P:-0}))
  TOTAL_FAIL=$((TOTAL_FAIL + ${F:-0}))
done
echo "=== ROUND $ROUND done $(date '+%F %T') summary: TOTAL_PASS=$TOTAL_PASS TOTAL_FAIL=$TOTAL_FAIL ===" | tee -a "$LOG"
if [ -f "$OUT/FAILED" ]; then
  echo "ROUND $ROUND RESULT: FAILED" | tee -a "$LOG"
  exit 1
fi
echo "ROUND $ROUND RESULT: ALL_PASS (PASS=$TOTAL_PASS)" | tee -a "$LOG"
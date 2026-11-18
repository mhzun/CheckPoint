#!/bin/bash
# 攻击性测试（fuzz / 负载 / 请求走私）—— 使用高限流测试实例，结果写 test-results/attack/
set -u
cd /opt/checkpoint || exit 1
OUT="/opt/checkpoint/test-results/attack"
mkdir -p "$OUT"
COMPOSE="docker compose -f docker-compose.test-hi.yml"
LOG="$OUT/run.log"
echo "=== ATTACK TESTS start $(date '+%F %T') ===" | tee -a "$LOG"

wait_healthy() {
  for i in $(seq 1 60); do
    if $COMPOSE exec -T checkpoint-test-hi \
        python -c "import socket; socket.create_connection(('127.0.0.1',8000),3).close()" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

$COMPOSE down > /dev/null 2>&1
$COMPOSE up -d --force-recreate > /dev/null 2>&1
wait_healthy || { echo "HI ENV UNHEALTHY"; exit 2; }

echo "--- fuzz campaign ---" | tee -a "$LOG"
$COMPOSE exec -T checkpoint-test-hi \
  python scripts/fuzz_campaign.py 500 > "$OUT/fuzz.json" 2>&1
echo "fuzz exit=$? -> $OUT/fuzz.json" | tee -a "$LOG"

echo "--- request smuggling probes ---" | tee -a "$LOG"
$COMPOSE exec -T checkpoint-test-hi \
  python scripts/smuggling_probe.py > "$OUT/smuggling.json" 2>&1
echo "smuggling exit=$? -> $OUT/smuggling.json" | tee -a "$LOG"

echo "--- load test 50x10s ---" | tee -a "$LOG"
$COMPOSE exec -T checkpoint-test-hi \
  python scripts/load_test.py 50 10 > "$OUT/load-50.json" 2>&1
echo "load exit=$? -> $OUT/load-50.json" | tee -a "$LOG"

echo "--- load test 100x10s ---" | tee -a "$LOG"
$COMPOSE exec -T checkpoint-test-hi \
  python scripts/load_test.py 100 10 > "$OUT/load-100.json" 2>&1
echo "load exit=$? -> $OUT/load-100.json" | tee -a "$LOG"

$COMPOSE down > /dev/null 2>&1
echo "=== ATTACK TESTS done $(date '+%F %T') ===" | tee -a "$LOG"
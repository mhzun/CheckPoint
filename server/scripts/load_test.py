#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""轻量负载测试（v1.3.0）：多并发压 /verify 与 /health，输出 p50/p95/p99、RPS、错误率。
在容器内执行（使用 RATE_IP_LIMIT 放大后的测试实例）。

用法: python scripts/load_test.py [并发数] [持续秒数] [BASE_URL]
"""
import json
import os
import queue
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

CONC = int(sys.argv[1]) if len(sys.argv) > 1 else 50
DURATION = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
BASE = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("BASE_URL", "https://127.0.0.1:8000")

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

latencies = []
status_counts = {}
lock = threading.Lock()
stop_at = 0.0


def worker():
    while time.time() < stop_at:
        if int(time.time() * 10) % 2 == 0:
            req = urllib.request.Request(BASE + "/health", method="GET")
        else:
            body = json.dumps({"token": "L" * 43, "machine_code": "LOAD-TEST"}).encode()
            req = urllib.request.Request(BASE + "/verify", data=body, method="POST")
            req.add_header("Content-Type", "application/json")
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as r:
                r.read(2048)
                st = r.status
        except urllib.error.HTTPError as e:
            try:
                e.read(2048)
            except Exception:
                pass
            st = e.code
        except Exception:
            st = -1
        dt = (time.monotonic() - t0) * 1000
        with lock:
            latencies.append(dt)
            status_counts[st] = status_counts.get(st, 0) + 1


def main():
    global stop_at
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(CONC)]
    stop_at = time.time() + DURATION
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lat = sorted(latencies)
    n = len(lat)

    def pct(p):
        return round(lat[min(n - 1, int(n * p))], 1) if n else 0

    result = {
        "concurrency": CONC,
        "duration_s": DURATION,
        "requests": n,
        "rps": round(n / DURATION, 1),
        "latency_ms": {"p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99),
                       "max": round(lat[-1], 1) if n else 0},
        "status_counts": {str(k): v for k, v in sorted(status_counts.items(), key=lambda kv: str(kv[0]))},
        "error_rate": round(sum(v for k, v in status_counts.items() if k == -1 or k >= 500) / max(n, 1), 4),
    }
    print(json.dumps(result, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
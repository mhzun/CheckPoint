#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""结构化 fuzz 战役（v1.3.0）：随机畸形请求打满全部端点，任何 5xx / 连接异常都算失败。
在容器内执行（使用 RATE_IP_LIMIT 放大后的测试实例）。

用法: python scripts/fuzz_campaign.py [迭代次数] [BASE_URL]
"""
import json
import os
import random
import ssl
import string
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("BASE_URL", "https://127.0.0.1:8000")
ITER = int(sys.argv[1]) if len(sys.argv) > 1 else 500
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

PATHS = ["/register", "/login", "/activate", "/verify", "/admin/gen_keys", "/admin/revoke",
         "/admin/rebind", "/admin/revoke_batch", "/health", "/docs", "/openapi.json"]
METHODS = ["POST", "GET", "PUT", "DELETE", "OPTIONS"]

UNICODE_POOL = [
    "\u0000", "\ud800", "\udfff", "\uFFFD", "中文", "🖥️", "Ａ", "ＡＢＣ", "&#x27;",
    "a" * 500, "VIP-" + "A" * 8 + "-" + "B" * 8 + "-" + "C" * 8,
    "VIP-IIIIIIII-OOOOOOOO-00000000", "' OR 1=1 --", "\r\n", "\t\x01\x7f", "NaN", "Infinity",
]


def hdr_safe(value: str) -> str:
    """HTTP 头只能是 latin-1 且不含 CR/LF/控制字符；统一清洗（避免 fuzz 客户端自身异常）。"""
    cleaned = "".join(ch for ch in value if 0x20 <= ord(ch) <= 0xFF)
    return cleaned.encode("latin-1", "ignore").decode("latin-1")


def rand_str():
    kind = random.random()
    if kind < 0.5:
        return random.choice(UNICODE_POOL)
    return "".join(random.choice(string.printable) for _ in range(random.randint(0, 40)))


def rand_value(depth=0):
    r = random.random()
    if depth > 3:
        return rand_str()
    if r < 0.35:
        return rand_str()
    if r < 0.5:
        return random.choice([None, True, False])
    if r < 0.7:
        return random.choice([0, -1, 1, 100, 101, 2 ** 63, -2 ** 63, 1.5, 3650, 3651])
    if r < 0.85:
        return [rand_value(depth + 1) for _ in range(random.randint(0, 3))]
    return {rand_str()[:10]: rand_value(depth + 1) for _ in range(random.randint(0, 3))}


def rand_body():
    r = random.random()
    if r < 0.7:
        return json.dumps({rand_str()[:12]: rand_value() for _ in range(random.randint(0, 4))},
                          ensure_ascii=False).encode("utf-8", errors="surrogatepass")
    if r < 0.85:
        return bytes(random.randint(0, 255) for _ in range(random.randint(0, 64)))
    # 深层嵌套（受 16KB 上限约束）
    depth = random.randint(100, 3000)
    return ("[" * depth + "]" * depth).encode()


def one_request(i):
    path = random.choice(PATHS)
    method = random.choice(METHODS)
    body = rand_body() if method in ("POST", "PUT") else None
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", random.choice(
            ["application/json", "text/plain", "application/json; charset=utf-16", "application/x-www-form-urlencoded"]))
    if random.random() < 0.3:
        req.add_header("X-Forwarded-For", hdr_safe(rand_str())[:40].replace("\r", "").replace("\n", ""))
    if random.random() < 0.15:
        req.add_header("X-Admin-Key", ADMIN_KEY if random.random() < 0.5 else hdr_safe(rand_str())[:80])
    if random.random() < 0.1:
        req.add_header("X-Client-Version", hdr_safe(rand_str())[:20].replace("\r", "").replace("\n", ""))
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CTX) as r:
            r.read(4096)
            return r.status, time.monotonic() - t0, None
    except urllib.error.HTTPError as e:
        try:
            e.read(4096)
        except Exception:
            pass
        return e.code, time.monotonic() - t0, None
    except ssl.SSLError as e:
        return -2, time.monotonic() - t0, repr(e)[:80]  # TLS 层拒绝（如超大头部）可接受
    except Exception as e:
        return -1, time.monotonic() - t0, repr(e)[:80]


def main():
    stats = {}
    failures = []
    slow = 0
    t_start = time.time()
    for i in range(ITER):
        st, dt, err = one_request(i)
        stats[st] = stats.get(st, 0) + 1
        if dt > 5:
            slow += 1
        if st >= 500:
            failures.append((i, st, err))
        if st == -1:
            failures.append((i, st, err))
    elapsed = time.time() - t_start
    print(json.dumps({
        "iterations": ITER,
        "elapsed_s": round(elapsed, 1),
        "rps": round(ITER / elapsed, 1),
        "status_counts": {str(k): v for k, v in sorted(stats.items(), key=lambda kv: str(kv[0]))},
        "slow_>5s": slow,
        "failures": failures[:10],
        "failure_count": len(failures),
        "result": "PASS" if not failures else "FAIL",
    }, ensure_ascii=False, indent=1))
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
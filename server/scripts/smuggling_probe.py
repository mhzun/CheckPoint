#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP 请求走私探测（v1.3.0）：CL.TE / TE.CL / 重复 CL / 畸形 framing。
直接打 uvicorn（无中间代理时为基线；生产加反代后需在反代层复测）。

通过标准：
- 任何含糊 framing 的请求都必须被拒绝（4xx/连接关闭），绝不能返回 2xx；
- 含糊请求之后的管道化请求不得被当作独立合法请求处理（无 desync）。
"""
import json
import socket
import ssl
import sys

HOST = "127.0.0.1"
PORT = 8000

CASES = [
    ("CL+TE 冲突（CL.TE）",
     b"POST /verify HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n"
     b"Connection: close\r\n\r\n0\r\n\r\n"),
    ("TE.CL 冲突（chunked 后藏第二个请求）",
     b"POST /verify HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\nTransfer-Encoding: chunked\r\n"
     b"Connection: close\r\n\r\n0\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\n\r\n"),
    ("重复 Content-Length",
     b"POST /verify HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 8\r\n"
     b"Connection: close\r\n\r\nABCD"),
    ("非法 Content-Length（+号）",
     b"POST /verify HTTP/1.1\r\nHost: x\r\nContent-Length: +4\r\nConnection: close\r\n\r\nABCD"),
    ("非法 Transfer-Encoding 值",
     b"POST /verify HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: xchunked\r\n"
     b"Connection: close\r\n\r\nABCD"),
    ("管道化走私（模糊请求 + 跟随请求）",
     b"POST /verify HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
     b"0\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\n\r\n"),
]


def probe(payload: bytes):
    raw = socket.create_connection((HOST, PORT), timeout=10)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname=HOST)
    s.sendall(payload)
    s.settimeout(5)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return data


def main():
    ok = True
    for name, payload in CASES:
        resp = probe(payload)
        first_line = resp.split(b"\r\n", 1)[0].decode("latin-1", errors="replace") if resp else "<no response>"
        two_responses = resp.count(b"HTTP/1.1 ") > 1
        rejected = (not resp) or b" 4" in first_line.encode() or b" 5" in first_line.encode()
        passed = rejected and not two_responses
        ok = ok and passed
        print(json.dumps({
            "case": name, "first_line": first_line,
            "responses_in_stream": resp.count(b"HTTP/1.1 "),
            "verdict": "PASS" if passed else "FAIL",
        }, ensure_ascii=False))
    print(json.dumps({"result": "PASS" if ok else "FAIL"}))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
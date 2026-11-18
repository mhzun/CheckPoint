#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CheckPoint 服务端端到端测试（标准库 + cryptography 验签，无其他依赖）。

用法（在容器内 /app 下执行，或外部指定 BASE_URL / DB_PATH / ADMIN_KEY）：
    python test_api.py func      # 业务功能 + 安全红线（v1.1.0：重新激活、token 哈希）
    python test_api.py escape    # machine_code 特殊字符与参数化存储
    python test_api.py race      # 同卡密并发激活原子性
    python test_api.py sig       # 响应签名（ECDSA P-256）+ nonce 回显
    python test_api.py security  # 文档关闭/413/安全头/登录限流/TTL/撤销/迁移等
    python test_api.py spoof     # XFF 伪造不生效（需 TRUST_PROXY=0，需重启后执行）
    python test_api.py mc        # 同 machine_code 激活限流（需重启服务后执行）
    python test_api.py ip        # 同 IP 限流（需重启服务后执行）

每个阶段之间建议重启服务（限流桶在进程内存中）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = os.environ.get("BASE_URL", "http://127.0.0.1:8000")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "TEST-ONLY-KEY-not-for-production")
DB_PATH = os.environ.get("DB_PATH", "/data/checkpoint.db")
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"

# 自签名证书环境（容器内 https://127.0.0.1:8000）需要跳过系统校验，
# 证书指纹锁定由真实客户端（checkpoint.exe）的端到端测试覆盖。
_SSL_CTX = None


def _ssl_ctx():
    global _SSL_CTX
    if BASE.startswith("https"):
        if _SSL_CTX is None:
            _SSL_CTX = ssl.create_default_context()
            _SSL_CTX.check_hostname = False
            _SSL_CTX.verify_mode = ssl.CERT_NONE
        return _SSL_CTX
    return None

# 与客户端内置公钥一致（v1.1.0 签名密钥对的公钥，SPKI DER base64）
PUBKEY_B64 = ("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf1CVWx8assqziHp/D30BZAh/"
              "AaI24ej/k3uD96gSBJtjCpgVVKSohxOUynJIHENoJuTRUkWAHs/0tcpN4oxAOQ==")

KEY_RE = re.compile(r"^VIP-[A-HJ-NP-Z2-9]{8}-[A-HJ-NP-Z2-9]{8}-[A-HJ-NP-Z2-9]{8}$")

passed = 0
failed = 0
failures: list[str] = []


def _call_once(path: str, payload: dict | bytes | None = None, headers: dict | None = None,
               method: str = "POST"):
    """返回 (status, body_dict, headers_message)。payload 可以是 dict 或原始字节。"""
    data = None
    if isinstance(payload, (dict,)):
        data = json.dumps(payload).encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        data = bytes(payload)
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as resp:
            raw = resp.read().decode("utf-8")
            try:
                body = json.loads(raw)
            except ValueError:
                body = {"raw": raw}
            return resp.status, body, resp.headers
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(raw)
        except ValueError:
            body = {"raw": raw}
        return exc.code, body, exc.headers
    except Exception as exc:  # 连接失败等
        return -1, {"error": repr(exc)}, None


# 功能测试请求数会超过 IP 限额（30/分钟），命中 429 时自动等待窗口滑过后重试
_RETRY_429 = False
_retry_count = 0


def call(path: str, payload: dict | bytes | None = None, headers: dict | None = None,
         method: str = "POST"):
    global _retry_count
    status, body, resp_headers = _call_once(path, payload, headers, method)
    if status == 429 and _RETRY_429 and _retry_count < 6:
        _retry_count += 1
        print(f"  [WAIT] 触发 IP 限流，等待 62 秒后重试（{_retry_count}/6）")
        time.sleep(62.0)
        status, body, resp_headers = _call_once(path, payload, headers, method)
    return status, body


def call_full(path: str, payload: dict | bytes | None = None, headers: dict | None = None,
              method: str = "POST"):
    """不做 429 重试，返回 (status, body, headers)。"""
    return _call_once(path, payload, headers, method)


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        failures.append(f"{name} :: {detail}")
        print(f"  [FAIL] {name} :: {detail}")


def expect(name: str, path: str, payload, status: int, code: int, msg_part: str | None = None,
           headers: dict | None = None, method: str = "POST"):
    st, body = call(path, payload, headers, method)
    ok_status = st == status
    ok_code = body.get("code") == code
    ok_msg = (msg_part is None) or (msg_part in str(body.get("msg", "")))
    check(name, ok_status and ok_code and ok_msg, f"实际 status={st} body={body}")
    return body


def db_rows(sql: str, params: tuple = ()):
    conn = sqlite3.connect(DB_PATH)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def gen_nonce() -> str:
    return secrets_token_urlsafe(16)


def secrets_token_urlsafe(nbytes: int) -> str:
    import secrets as _secrets
    return _secrets.token_urlsafe(nbytes)


def verify_signature(body_bytes: bytes, sig_b64: str) -> bool:
    """用内置公钥验证服务端签名（与客户端同一验证逻辑）。"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    pub = load_der_public_key(base64.b64decode(PUBKEY_B64))
    try:
        pub.verify(base64.b64decode(sig_b64), body_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def get_header(headers, name: str) -> str | None:
    if headers is None:
        return None
    try:
        return headers.get(name)
    except AttributeError:
        return None


def admin_gen_keys(count: int = 1, expire_days: int = 30) -> list[str]:
    st, body = call("/admin/gen_keys", {"count": count, "expire_days": expire_days},
                    {"X-Admin-Key": ADMIN_KEY})
    keys = (body.get("data") or {}).get("keys") or []
    if not keys:
        print(f"  [FATAL] 生成卡密失败：{st} {body}")
        sys.exit(1)
    return keys


# --------------------------------------------------------------------------- #

def stage_func() -> None:
    global _RETRY_429
    _RETRY_429 = True
    # 清理历史轮次遗留的测试用户（VM 生产库中可能有早期测试残留，不影响真实用户）
    _conn = sqlite3.connect(DB_PATH)
    _conn.execute("DELETE FROM users WHERE username IN "
                  "('alice_01','bob_01','sig_user_1','throttle_user1','ctl_user01','surro_user1')")
    _conn.commit()
    _conn.close()

    print("== 0. 探针 ==")
    st, body, hdr = call_full("/health", None, method="GET")
    check("GET /health 正常", st == 200 and body.get("code") == 0 and body.get("msg") == "服务正常", f"{st} {body}")
    check("/health 不携带签名头", get_header(hdr, "X-Signature") is None, str(get_header(hdr, "X-Signature")))

    print("== 1. /register 注册 ==")
    expect("注册成功", "/register", {"username": "alice_01", "password": "Passw0rd!23"}, 200, 0, "注册成功")
    body = expect("用户名重复", "/register", {"username": "alice_01", "password": "Passw0rd!23"}, 200, 1, "用户名已存在")
    expect("用户名过短(2位)", "/register", {"username": "ab", "password": "Passw0rd!23"}, 200, 1, "用户名")
    expect("用户名过长(33位)", "/register", {"username": "a" * 33, "password": "Passw0rd!23"}, 200, 1, "用户名")
    expect("用户名含非法字符", "/register", {"username": "alice 01!", "password": "Passw0rd!23"}, 200, 1, "用户名")
    expect("密码过短(7位)", "/register", {"username": "bob_01", "password": "Pass07!"}, 200, 1, "密码")
    expect("密码过长(65位)", "/register", {"username": "bob_01", "password": "p" * 65}, 200, 1, "密码")
    expect("密码超 bcrypt 72 字节", "/register", {"username": "bob_01", "password": "密" * 30}, 200, 1, "密码")
    expect("字段缺失 -> 422", "/register", {"username": "bob_01"}, 422, 1, "请求参数缺失")
    expect("字段类型错误 -> 422", "/register", {"username": 123, "password": "Passw0rd!23"}, 422, 1, "请求参数缺失")

    print("== 2. 数据库：密码必须是 bcrypt(rounds=12) ==")
    rows = db_rows("SELECT username, password_hash FROM users WHERE username = ?", ("alice_01",))
    check("用户已入库", len(rows) == 1, f"rows={rows}")
    if rows:
        ph = rows[0][1]
        check("哈希以 $2b$12$ 开头", ph.startswith("$2b$12$"), ph[:20])
        check("哈希长度 60", len(ph) == 60, str(len(ph)))
        check("不含明文密码", "Passw0rd!23" not in ph, ph)

    print("== 3. /login 登录 ==")
    st, body = call("/login", {"username": "alice_01", "password": "Passw0rd!23"})
    token = (body.get("data") or {}).get("token")
    check("登录成功", st == 200 and body.get("code") == 0 and body.get("msg") == "登录成功", f"{st} {body}")
    check("token 由 token_urlsafe(32) 生成（43 位）", isinstance(token, str) and len(token) == 43, str(token))
    rows = db_rows("SELECT token_hash FROM activations WHERE license_key IS NULL ORDER BY id DESC LIMIT 1")
    check("登录 token 以 SHA-256 哈希入库（64 位 hex）",
          bool(rows) and re.fullmatch(r"[0-9a-f]{64}", rows[0][0] or "") is not None, str(rows))
    check("入库哈希等于 sha256(token)", bool(rows) and rows[0][0] == hash_token(token or ""), str(rows))
    expect("密码错误", "/login", {"username": "alice_01", "password": "WrongPass!"}, 200, 1, "用户名或密码错误")
    expect("用户不存在", "/login", {"username": "nobody_99", "password": "Passw0rd!23"}, 200, 1, "用户名或密码错误")
    expect("用户不存在与密码错误文案完全一致",
           "/login", {"username": "nobody_99", "password": "Passw0rd!23"}, 200, 1, "用户名或密码错误")
    if token:
        st, vbody = call("/verify", {"token": token, "machine_code": "login-machine"})
        check("登录 token 可通过 /verify", st == 200 and vbody.get("code") == 0, f"{st} {vbody}")

    print("== 3b. 登录单会话（v1.3.0：新登录注销旧登录 token）==")
    st, body2 = call("/login", {"username": "alice_01", "password": "Passw0rd!23"})
    token2 = (body2.get("data") or {}).get("token")
    check("第二次登录成功", st == 200 and body2.get("code") == 0, f"{st} {body2}")
    if token and token2:
        st, v1 = call("/verify", {"token": token, "machine_code": "login-machine"})
        st2, v2 = call("/verify", {"token": token2, "machine_code": "login-machine"})
        check("旧登录 token 已被注销", v1.get("code") == 1, f"{v1}")
        check("新登录 token 有效", v2.get("code") == 0, f"{v2}")
        rows = db_rows("SELECT COUNT(*) FROM activations WHERE license_key IS NULL AND user_id = "
                       "(SELECT id FROM users WHERE username = ?)", ("alice_01",))
        check("该用户仅存 1 个登录 token 行", rows and rows[0][0] == 1, str(rows))

    print("== 4. /admin/gen_keys 管理员鉴权 ==")
    expect("缺少 X-Admin-Key -> 403", "/admin/gen_keys", {"count": 2, "expire_days": 30}, 403, 1, "无权限访问")
    expect("错误的 X-Admin-Key -> 403", "/admin/gen_keys", {"count": 2, "expire_days": 30},
           403, 1, "无权限访问", headers={"X-Admin-Key": "wrong-key"})
    keys = admin_gen_keys(3, 30)
    check("生成数量正确", len(keys) == 3, str(keys))
    check("卡密格式正确", all(KEY_RE.match(k) for k in keys), str(keys))
    randoms = ["".join(k.split("-")[1:]) for k in keys]
    check("卡密随机部分 24 位且无易混淆字符",
          all(len(r) == 24 and not (set(r) & set("IO01")) for r in randoms), str(keys))
    expect("count 越界(0)", "/admin/gen_keys", {"count": 0, "expire_days": 30}, 200, 1, "生成数量",
           headers={"X-Admin-Key": ADMIN_KEY})
    expect("count 越界(101)", "/admin/gen_keys", {"count": 101, "expire_days": 30}, 200, 1, "生成数量",
           headers={"X-Admin-Key": ADMIN_KEY})
    expect("expire_days 越界(0)", "/admin/gen_keys", {"count": 1, "expire_days": 0}, 200, 1, "有效期",
           headers={"X-Admin-Key": ADMIN_KEY})
    expect("expire_days 越界(3651)", "/admin/gen_keys", {"count": 1, "expire_days": 3651}, 200, 1, "有效期",
           headers={"X-Admin-Key": ADMIN_KEY})

    print("== 5. /activate 激活 ==")
    keys = admin_gen_keys(3, 30)
    key_ok = keys[0]
    key_react = keys[1]
    st, abody = call("/activate", {"key": key_ok, "machine_code": "MACHINE-AAA-001"})
    act_token = (abody.get("data") or {}).get("token")
    check("激活成功", st == 200 and abody.get("code") == 0 and abody.get("msg") == "激活成功", f"{st} {abody}")
    check("激活 token 长度 43", isinstance(act_token, str) and len(act_token) == 43, str(act_token))

    rows = db_rows('SELECT status, bound_machine FROM licenses WHERE "key" = ?', (key_ok,))
    check("卡密状态置为 used", rows and rows[0][0] == "used", str(rows))
    check("已绑定机器码", rows and rows[0][1] == "MACHINE-AAA-001", str(rows))

    rows = db_rows("SELECT token_hash FROM activations WHERE license_key = ? ORDER BY id DESC LIMIT 1", (key_ok,))
    check("激活 token 以 SHA-256 哈希入库（64 位 hex）",
          bool(rows) and re.fullmatch(r"[0-9a-f]{64}", rows[0][0] or "") is not None, str(rows))
    check("入库哈希等于 sha256(token)", bool(rows) and rows[0][0] == hash_token(act_token or ""), str(rows))

    # 已用卡密换机器（改绑宽限期已过）/ 不存在卡密 / 格式非法：三者文案必须完全一致
    # v1.3.0：宽限期内允许改绑（见 rebind 阶段），这里把 bound_at 改成早已过期来测严格拒绝
    key_mismatch = keys[2]
    call("/activate", {"key": key_mismatch, "machine_code": "MISMATCH-A"})
    conn = sqlite3.connect(DB_PATH)
    conn.execute('UPDATE licenses SET bound_at = ? WHERE "key" = ?',
                 ("2000-01-01T00:00:00Z", key_mismatch))
    conn.commit()
    conn.close()
    st1, b1 = call("/activate", {"key": key_mismatch, "machine_code": "MISMATCH-B"})
    st2, b2 = call("/activate", {"key": "VIP-AAAAAAAA-BBBBBBBB-CCCCCCCC", "machine_code": "MACHINE-XYZ"})
    st3, b3 = call("/activate", {"key": "VIP-0000-1111-2222", "machine_code": "MACHINE-XYZ"})
    check("已用卡密换机器（宽限期已过）-> 卡密无效或已失效", st1 == 200 and b1.get("code") == 1 and b1.get("msg") == "卡密无效或已失效", f"{st1} {b1}")
    check("不存在卡密 -> 卡密无效或已失效", st2 == 200 and b2.get("code") == 1 and b2.get("msg") == "卡密无效或已失效", f"{st2} {b2}")
    check("格式非法卡密 -> 卡密无效或已失效", st3 == 200 and b3.get("code") == 1 and b3.get("msg") == "卡密无效或已失效", f"{st3} {b3}")
    check("三种失败响应体完全一致", b1 == b2 == b3, f"{b1} / {b2} / {b3}")
    check("失败响应不含可区分信息", set(b1.keys()) == {"code", "msg", "data"}, str(b1))

    # 后续边界测试用不同机器码打 key_ok：先把改绑宽限期置为过期，确保不同机器码被拒
    conn = sqlite3.connect(DB_PATH)
    conn.execute('UPDATE licenses SET bound_at = ? WHERE "key" = ?',
                 ("2000-01-01T00:00:00Z", key_ok))
    conn.commit()
    conn.close()

    expect("小写卡密应归一化后可用/不可用一致", "/activate",
           {"key": "vip-aaaaaaaa-bbbbbbbb-cccccccc", "machine_code": "M"}, 200, 1, "卡密无效或已失效")
    expect("包含 I/O/0/1 的卡密被拒", "/activate",
           {"key": "VIP-IIIIIIII-OOOOOOOO-00000000", "machine_code": "M"}, 200, 1, "卡密无效或已失效")
    expect("machine_code 为空", "/activate", {"key": key_ok, "machine_code": ""}, 200, 1, "机器码不能为空")
    expect("machine_code 仅空白", "/activate", {"key": key_ok, "machine_code": "   "}, 200, 1, "机器码不能为空")
    expect("machine_code 超 128 位", "/activate", {"key": key_ok, "machine_code": "x" * 129}, 200, 1, "128")
    st, b = call("/activate", {"key": key_ok, "machine_code": "y" * 128})
    check("machine_code 恰好 128 位被接受（业务失败但不报长度）", "128" not in str(b.get("msg")), str(b))
    expect("卡密字段缺失 -> 422", "/activate", {"machine_code": "M"}, 422, 1, "请求参数缺失")

    # 注入尝试：参数化查询下应安全（当作不存在的卡密处理）
    sqli = "VIP-AAAAAAAA-BBBBBBBB-CCCCCCCC' OR '1'='1"
    expect("SQL 注入尝试无效", "/activate", {"key": sqli, "machine_code": "M"}, 200, 1, "卡密无效或已失效")

    print("== 6. /verify 验证 ==")
    st, vbody = call("/verify", {"token": act_token, "machine_code": "MACHINE-AAA-001"})
    check("验证通过", st == 200 and vbody.get("code") == 0 and vbody.get("data") == {"valid": True}, f"{st} {vbody}")
    st, vbody = call("/verify", {"token": act_token, "machine_code": "MACHINE-BBB"})
    check("机器码不匹配 -> 验证失败", st == 200 and vbody.get("code") == 1 and vbody.get("msg") == "验证失败", f"{st} {vbody}")
    st, vbody = call("/verify", {"token": "A" * 43, "machine_code": "MACHINE-AAA-001"})
    check("token 不存在 -> 验证失败", st == 200 and vbody.get("code") == 1 and vbody.get("msg") == "验证失败", f"{st} {vbody}")
    st, vbody = call("/verify", {"token": act_token})
    check("缺 machine_code -> 422", st == 422 and vbody.get("code") == 1, f"{st} {vbody}")
    st, vbody = call("/verify", {"token": "bad token!!", "machine_code": "M"})
    check("token 格式非法 -> 验证失败", st == 200 and vbody.get("code") == 1, f"{st} {vbody}")

    rows = db_rows("SELECT license_key, machine_code, token_hash, last_seen FROM activations WHERE token_hash = ?",
                   (hash_token(act_token),))
    check("激活关系已记录", len(rows) == 1 and rows[0][0] == key_ok and rows[0][1] == "MACHINE-AAA-001", str(rows))

    print("== 7. 过期卡密 ==")
    conn = sqlite3.connect(DB_PATH)
    # 固定测试卡密：先清理上一轮残留再插入（幂等，支持多轮回归）
    conn.execute('DELETE FROM licenses WHERE "key" = ?', ("VIP-EXPIRED1-EXPIRED2-EXPIRED3",))
    conn.execute(
        'INSERT INTO licenses ("key", status, expire_at, bound_machine, created_at) VALUES (?, ?, ?, NULL, ?)',
        ("VIP-EXPIRED1-EXPIRED2-EXPIRED3", "unused", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()
    expect("过期卡密 -> 卡密无效或已失效", "/activate",
           {"key": "VIP-EXPIRED1-EXPIRED2-EXPIRED3", "machine_code": "M-EXP"}, 200, 1, "卡密无效或已失效")
    check("过期卡密仍保持 unused 状态",
          db_rows('SELECT status FROM licenses WHERE "key" = ?', ("VIP-EXPIRED1-EXPIRED2-EXPIRED3",))[0][0] == "unused")

    print("== 8. 重新激活（同机器找回 token） ==")
    st, abody = call("/activate", {"key": key_react, "machine_code": "REACT-MACHINE-X"})
    react_token_1 = (abody.get("data") or {}).get("token")
    check("首次激活成功", st == 200 and abody.get("code") == 0, f"{st} {abody}")
    st, abody = call("/activate", {"key": key_react, "machine_code": "REACT-MACHINE-X"})
    react_token_2 = (abody.get("data") or {}).get("token")
    check("同机器重新激活成功", st == 200 and abody.get("code") == 0, f"{st} {abody}")
    check("重新激活补发新 token", react_token_1 and react_token_2 and react_token_1 != react_token_2,
          f"{react_token_1} vs {react_token_2}")
    rows = db_rows('SELECT bound_machine FROM licenses WHERE "key" = ?', (key_react,))
    check("绑定机器保持不变", rows and rows[0][0] == "REACT-MACHINE-X", str(rows))
    if react_token_1 and react_token_2:
        st, v1 = call("/verify", {"token": react_token_1, "machine_code": "REACT-MACHINE-X"})
        st2, v2 = call("/verify", {"token": react_token_2, "machine_code": "REACT-MACHINE-X"})
        check("两个 token 均可验证（同机器）", v1.get("code") == 0 and v2.get("code") == 0, f"{v1} / {v2}")
    # 宽限期已过：换机器重新激活必须被拒（v1.3.0 改绑策略）
    conn = sqlite3.connect(DB_PATH)
    conn.execute('UPDATE licenses SET bound_at = ? WHERE "key" = ?',
                 ("2000-01-01T00:00:00Z", key_react))
    conn.commit()
    conn.close()
    expect("换机器重新激活被拒（宽限期已过）", "/activate",
           {"key": key_react, "machine_code": "REACT-MACHINE-Y"}, 200, 1, "卡密无效或已失效")

    print("== 9. 数据库字段长度与转义（machine_code 截断/清洗）==")
    cleaned_input = "  <script>alert(1)</script> & 'quote'  "
    st, b = call("/activate", {"key": "VIP-AAAAAAAA-BBBBBBBB-CCCCCCCC", "machine_code": cleaned_input})
    check("恶意 machine_code 不触发 500", st in (200, 429), f"{st} {b}")

    print(f"\n结果：PASS={passed} FAIL={failed}")
    if failures:
        for f in failures:
            print("  - " + f)
        sys.exit(1)


def stage_mc() -> None:
    """同一 machine_code 每分钟最多 10 次激活尝试。"""
    print("== machine_code 限流（同 mc 10 次/分钟）==")
    key = admin_gen_keys(1, 30)[0]
    codes = []
    for i in range(12):
        st, b = call("/activate", {"key": key, "machine_code": "RATE-MC-FIXED"})
        codes.append(st)
    print("  状态码序列:", codes)
    check("前 10 次未被限流", all(c in (200,) for c in codes[:10]), str(codes[:10]))
    check("第 11、12 次返回 429", codes[10] == 429 and codes[11] == 429, str(codes[10:]))
    st, b = call("/activate", {"key": key, "machine_code": "RATE-MC-OTHER"})
    check("换 machine_code 不受该桶影响", st == 200, f"{st} {b}")
    print(f"\n结果：PASS={passed} FAIL={failed}")
    if failures:
        for f in failures:
            print("  - " + f)
        sys.exit(1)


def stage_ip() -> None:
    """同一 IP 每分钟最多 30 次请求（/health 不计入）。用 /verify（轻量路径）压测。"""
    print("== IP 限流（同 IP 30 次/分钟）==")
    for _ in range(5):
        call("/health", None, method="GET")
    codes = []
    for _ in range(32):
        st, b = call("/verify", {"token": "I" * 43, "machine_code": "rate-machine"})
        codes.append(st)
    print("  状态码序列:", codes)
    check("前 30 次未被限流", all(c == 200 for c in codes[:30]), str(codes[:30]))
    check("第 31、32 次返回 429", codes[30] == 429 and codes[31] == 429, str(codes[30:]))
    st, b = call("/health", None, method="GET")
    check("/health 不受限流影响", st == 200, f"{st} {b}")
    print(f"\n结果：PASS={passed} FAIL={failed}")
    if failures:
        for f in failures:
            print("  - " + f)
        sys.exit(1)


def stage_escape() -> None:
    """machine_code 含特殊字符：参数化存储、长度内不清洗内容、可复用验证。"""
    print("== machine_code 特殊字符与参数化存储 ==")
    key = admin_gen_keys(1, 30)[0]
    mc = "  Machine's \"Code\" \\ <script>alert(1)</script> 中文  "
    st, ab = call("/activate", {"key": key, "machine_code": mc})
    token = (ab.get("data") or {}).get("token")
    check("含特殊字符的 machine_code 可正常激活", st == 200 and ab.get("code") == 0, f"{st} {ab}")
    rows = db_rows('SELECT bound_machine FROM licenses WHERE "key" = ?', (key,))
    check("机器码按原值参数化存储（首尾空白被裁剪）",
          bool(rows) and rows[0][0] == mc.strip(), str(rows))
    st, vb = call("/verify", {"token": token, "machine_code": mc})
    check("相同机器码可通过验证", st == 200 and vb.get("code") == 0, f"{st} {vb}")
    st, vb = call("/verify", {"token": token, "machine_code": mc.strip() + "x"})
    check("篡改机器码验证失败", vb.get("code") == 1, f"{st} {vb}")
    check("表结构未被注入破坏（三表健在）",
          len(db_rows("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users','licenses','activations')")) == 3)
    print(f"\n结果：PASS={passed} FAIL={failed}")
    if failures:
        for f in failures:
            print("  - " + f)
        sys.exit(1)


def stage_race() -> None:
    """同一卡密并发激活（不同机器码）。v1.3.0 宽限期内允许多次改绑，但必须始终：
    - 最终只有一个绑定机器
    - 只有最终绑定机器对应的最新 token 有效（旧 token 被改绑注销）
    - 无 5xx / 无数据损坏"""
    print("== 并发激活一致性（5 并发，同卡密不同机器，宽限期内改绑）==")
    key = admin_gen_keys(1, 30)[0]

    results: list = []
    guard = threading.Lock()

    def worker(i: int) -> None:
        st, b, _h = _call_once("/activate", {"key": key, "machine_code": f"RACE-MACHINE-{i}"})
        with guard:
            results.append((i, st, b))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    codes = [b.get("code") for _, _, b in results]
    print("  业务码:", codes)
    check("至少 1 次激活成功", codes.count(0) >= 1, str(codes))
    check("无 5xx / 网络异常", all(st in (200, 429) for _, st, _ in results), str(results))

    row = db_rows('SELECT status, bound_machine FROM licenses WHERE "key" = ?', (key,))
    check("license 状态为 used", bool(row) and row[0][0] == "used", str(row))
    final_machine = row[0][1] if row else None
    check("最终绑定机器属于本次并发集合",
          final_machine in {f"RACE-MACHINE-{i}" for i in range(5)}, str(final_machine))

    acts = db_rows("SELECT token_hash FROM activations WHERE license_key = ?", (key,))
    check("该卡密仅 1 条有效激活记录（改绑注销旧 token）", len(acts) == 1, str(acts))

    # 只有最终机器对应的最新 token 可以通过验证
    last_ok = [b for i, st, b in results if b.get("code") == 0]
    if last_ok and final_machine:
        tok = (last_ok[-1].get("data") or {}).get("token")
        if tok:
            st1, v_ok = call("/verify", {"token": tok, "machine_code": final_machine})
            st2, v_bad = call("/verify", {"token": tok, "machine_code": "RACE-MACHINE-UNKNOWN"})
            check("最终 token+最终机器 验证通过", v_ok.get("code") == 0, f"{v_ok}")
            check("最终 token+其他机器 验证失败", v_bad.get("code") == 1, f"{v_bad}")

    print(f"\n结果：PASS={passed} FAIL={failed}")
    if failures:
        for f in failures:
            print("  - " + f)
        sys.exit(1)


def stage_sig() -> None:
    """响应签名（ECDSA P-256/SHA-256）+ nonce 回显。"""
    print("== 响应签名与 nonce ==")

    def assert_signed(name: str, path: str, payload: dict, headers: dict | None = None):
        nonce = gen_nonce()
        payload = dict(payload)
        payload["nonce"] = nonce
        st, body, hdr = call_full(path, payload, headers)
        raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        sig = get_header(hdr, "X-Signature")
        check(f"{name}: 携带 X-Signature", sig is not None, f"{st} headers={dict(hdr) if hdr else None}")
        if sig:
            # 用重新序列化的字节无法精确复现服务端原始字节，这里必须用原始响应字节
            # _call_once 已把响应解析成 dict，因此单独再发一次原始请求取原始字节
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(BASE + path, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as resp:
                raw = resp.read()
                sig2 = resp.headers.get("X-Signature")
                echoed = json.loads(raw.decode("utf-8")).get("nonce")
            check(f"{name}: 签名可由内置公钥验证", verify_signature(raw, sig2), "签名验证失败")
            check(f"{name}: nonce 正确回显", echoed == nonce, f"echoed={echoed} expect={nonce}")
        return st, body

    key = admin_gen_keys(1, 30)[0]
    assert_signed("/activate", "/activate", {"key": key, "machine_code": "SIG-MACHINE-1"})
    # 多轮回归时用户可能已存在：两种结果都可接受（幂等）
    st, body = call("/register", {"username": "sig_user_1", "password": "Passw0rd!23"})
    check("register 注册 sig 用户（已存在亦可）",
          st == 200 and body.get("code") == 0 and body.get("msg") == "注册成功"
          or body.get("msg") == "用户名已存在", f"{st} {body}")
    assert_signed("/login", "/login", {"username": "sig_user_1", "password": "Passw0rd!23"})
    assert_signed("/admin/gen_keys", "/admin/gen_keys", {"count": 1, "expire_days": 30},
                  {"X-Admin-Key": ADMIN_KEY})

    # verify 的签名验证（用上面激活的 token）
    key2 = admin_gen_keys(1, 30)[0]
    nonce = gen_nonce()
    data = json.dumps({"key": key2, "machine_code": "SIG-MACHINE-2", "nonce": nonce}).encode("utf-8")
    req = urllib.request.Request(BASE + "/activate", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as resp:
        act = json.loads(resp.read().decode("utf-8"))
    token2 = (act.get("data") or {}).get("token")

    nonce = gen_nonce()
    data = json.dumps({"token": token2, "machine_code": "SIG-MACHINE-2", "nonce": nonce}).encode("utf-8")
    req = urllib.request.Request(BASE + "/verify", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as resp:
        raw = resp.read()
        sig = resp.headers.get("X-Signature")
        body = json.loads(raw.decode("utf-8"))
    check("/verify: 成功响应携带签名", body.get("code") == 0 and sig is not None, f"{body} sig={sig}")
    check("/verify: 签名验证通过", verify_signature(raw, sig), "签名验证失败")
    check("/verify: nonce 回显一致", body.get("nonce") == nonce, str(body.get("nonce")))

    # 篡改响应字节 → 签名必须失效
    tampered = raw[:-1] + bytes([raw[-1] ^ 0x01])
    check("篡改响应字节后签名失效", not verify_signature(tampered, sig), "篡改后签名仍然通过")

    # 不带 nonce 的请求：响应仍签名但不回显 nonce
    data = json.dumps({"token": token2, "machine_code": "SIG-MACHINE-2"}).encode("utf-8")
    req = urllib.request.Request(BASE + "/verify", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as resp:
        raw2 = resp.read()
        body2 = json.loads(raw2.decode("utf-8"))
    check("无 nonce 请求：响应仍签名", resp.headers.get("X-Signature") is not None, "缺少签名")
    check("无 nonce 请求：响应不回显 nonce 字段", "nonce" not in body2, str(body2))

    # 业务失败响应也签名
    data = json.dumps({"token": "F" * 43, "machine_code": "SIG-MACHINE-2", "nonce": gen_nonce()}).encode("utf-8")
    req = urllib.request.Request(BASE + "/verify", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as resp:
        raw3 = resp.read()
        sig3 = resp.headers.get("X-Signature")
        body3 = json.loads(raw3.decode("utf-8"))
    check("失败响应也携带有效签名", body3.get("code") == 1 and sig3 and verify_signature(raw3, sig3), f"{body3}")

    print(f"\n结果：PASS={passed} FAIL={failed}")
    if failures:
        for f in failures:
            print("  - " + f)
        sys.exit(1)


def stage_security() -> None:
    """文档关闭 / 请求体上限 / 安全头 / 登录限流 / token TTL / 撤销 / 迁移。"""
    print("== 交互式文档与 OpenAPI 已关闭 ==")
    for p in ("/docs", "/redoc", "/openapi.json"):
        st, body, _ = call_full(p, None, method="GET")
        check(f"GET {p} -> 404", st == 404, f"{st} {body}")

    print("== 请求体大小上限 ==")
    st, body, _ = call_full("/login", json.dumps(
        {"username": "big_body_user", "password": "Passw0rd!23", "pad": "x" * 40000}).encode("utf-8"),
        {"Content-Type": "application/json"})
    check("32KB 请求体 -> 413", st == 413 and body.get("msg") == "请求体过大", f"{st} {body}")

    print("== 安全响应头 ==")
    st, body, hdr = call_full("/health", None, method="GET")
    check("X-Content-Type-Options: nosniff", get_header(hdr, "X-Content-Type-Options") == "nosniff",
          str(get_header(hdr, "X-Content-Type-Options")))
    check("Cache-Control: no-store", "no-store" in (get_header(hdr, "Cache-Control") or ""),
          str(get_header(hdr, "Cache-Control")))
    check("X-Frame-Options: DENY", get_header(hdr, "X-Frame-Options") == "DENY",
          str(get_header(hdr, "X-Frame-Options")))
    check("Content-Security-Policy 已设置", "default-src 'none'" in (get_header(hdr, "Content-Security-Policy") or ""),
          str(get_header(hdr, "Content-Security-Policy")))
    st, body, hdr = call_full("/login", {"username": "nobody_hdr", "password": "WrongPass!"})
    check("业务失败响应同样带安全头", get_header(hdr, "X-Content-Type-Options") == "nosniff",
          str(get_header(hdr, "X-Content-Type-Options")))

    print("== 登录失败限流（同用户名+IP 8 次/分钟）==")
    st, b = call("/register", {"username": "throttle_user1", "password": "Passw0rd!23"})
    check("注册限流测试用户（已存在亦可）",
          b.get("code") == 0 or b.get("msg") == "用户名已存在", f"{st} {b}")
    codes = []
    for _ in range(9):
        st, b, _h = call_full("/login", {"username": "throttle_user1", "password": "WrongPass!"})
        codes.append(st)
    print("  状态码序列:", codes)
    check("前 8 次错误密码返回 200(code=1)", all(c == 200 for c in codes[:8]), str(codes))
    check("第 9 次被限流 429", codes[8] == 429, str(codes))
    st, b, _h = call_full("/login", {"username": "throttle_user1", "password": "Passw0rd!23"})
    check("限流期间正确密码也被拒绝", st == 429, f"{st} {b}")

    print("== token 滑动过期（TTL）==")
    old_token = "EXPIREDTESTTOKEN123456789012345"
    old_seen = "2020-01-01T00:00:00Z"
    conn = sqlite3.connect(DB_PATH)
    # 固定测试 token：先清理上一轮残留再插入（幂等，支持多轮回归）
    conn.execute("DELETE FROM activations WHERE token_hash = ?", (hash_token(old_token),))
    conn.execute(
        "INSERT INTO activations (license_key, token_hash, machine_code, created_at, last_seen)"
        " VALUES (?, ?, ?, ?, ?)",
        (None, hash_token(old_token), "", old_seen, old_seen),
    )
    conn.commit()
    conn.close()
    st, b = call("/verify", {"token": old_token, "machine_code": "ANY"})
    check("超过 TTL 的 token 验证失败", st == 200 and b.get("code") == 1, f"{st} {b}")
    rows = db_rows("SELECT id FROM activations WHERE token_hash = ?", (hash_token(old_token),))
    check("过期 token 记录已被清理", len(rows) == 0, str(rows))

    print("== 撤销（/admin/revoke）==")
    key = admin_gen_keys(1, 30)[0]
    st, ab = call("/activate", {"key": key, "machine_code": "REVOKE-MACHINE"})
    rv_token = (ab.get("data") or {}).get("token")
    check("撤销前激活成功", st == 200 and ab.get("code") == 0, f"{st} {ab}")
    expect("撤销卡密", "/admin/revoke", {"key": key}, 200, 0, "撤销成功", headers={"X-Admin-Key": ADMIN_KEY})
    expect("撤销后重新激活被拒", "/activate",
           {"key": key, "machine_code": "REVOKE-MACHINE"}, 200, 1, "卡密无效或已失效")
    st, b = call("/verify", {"token": rv_token, "machine_code": "REVOKE-MACHINE"})
    check("撤销后原 token 验证失败", st == 200 and b.get("code") == 1, f"{st} {b}")
    expect("撤销不存在的卡密", "/admin/revoke",
           {"key": "VIP-AAAAAAAA-BBBBBBBB-CCCCCCCC"}, 200, 1, "卡密不存在", headers={"X-Admin-Key": ADMIN_KEY})
    expect("撤销缺少管理员密钥 -> 403", "/admin/revoke", {"key": key}, 403, 1, "无权限访问")
    expect("撤销格式非法卡密", "/admin/revoke", {"key": "VIP-BAD"}, 200, 1, "卡密格式不正确",
           headers={"X-Admin-Key": ADMIN_KEY})

    print("== 陈旧 token 行主动清理（防表膨胀，v1.2.0）==")
    stale_token = "STALEROWTESTTOKEN12345678901234567"
    stale_seen = "2025-01-01T00:00:00Z"
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM activations WHERE token_hash = ?", (hash_token(stale_token),))
    conn.execute(
        "INSERT INTO activations (license_key, token_hash, machine_code, created_at, last_seen)"
        " VALUES (?, ?, ?, ?, ?)",
        (None, hash_token(stale_token), "", stale_seen, stale_seen),
    )
    conn.commit()
    conn.close()
    # 用登录触发清理（activate 的失败路径不执行清理，成功路径/登录路径才执行）
    call("/register", {"username": "purge_user01", "password": "Passw0rd!23"})
    call("/login", {"username": "purge_user01", "password": "Passw0rd!23"})
    rows = db_rows("SELECT id FROM activations WHERE token_hash = ?", (hash_token(stale_token),))
    check("激活时陈旧 token 行被主动清理", len(rows) == 0, str(rows))

    print("== slow-drip 总超时（防每秒喂 1 字节挂连接，v1.2.0）==")
    try:
        s = socket.create_connection(("127.0.0.1", 8000), timeout=30)
        head = (b"POST /activate HTTP/1.1\r\nHost: x\r\n"
                b"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n")
        s.sendall(head + b'{"key":')
        t0 = time.time()
        for _ in range(20):
            time.sleep(1.0)
            s.sendall(b"A")
        data = s.recv(4096)
        dt = time.time() - t0
        s.close()
        total_timeout = (b"408" in data[:40]) and dt < 25
        check(f"slow-drip 在总超时内被掐断（{dt:.1f}s，响应 408）", total_timeout, f"{dt:.1f}s {data[:60]!r}")
    except Exception as e:
        check("slow-drip 连接被服务器主动断开", True, repr(e)[:120])

    print("== 密码包含控制字符 / 孤立代理对 ==")
    st, b, _ = call_full("/register", json.dumps({"username": "ctl_user01", "password": "Passw0rd!\u0000"}).encode("utf-8"))
    check("含 NUL 的密码被拒（非 500）", st == 200 and b.get("code") == 1 and "控制字符" in str(b.get("msg")), f"{st} {b}")
    raw_body = b'{"username":"surro_user1","password":"abc\\ud800def12345"}'
    st, b, _ = call_full("/register", raw_body)
    # 安全要求：绝不能 500；pydantic-core 可能在 422（参数校验）拦截，业务层则 200+code=1
    check("孤立代理对密码被拒（非 500）",
          (st == 200 and b.get("code") == 1 and "非法字符" in str(b.get("msg")))
          or (st == 422 and b.get("code") == 1), f"{st} {b}")

    print("== 旧库 token 哈希迁移 ==")
    mig_db = os.environ.get("MIG_TEST_DB", "/tmp/checkpoint-migration-test.db")
    if os.path.exists(mig_db):
        os.remove(mig_db)
    mig_conn = sqlite3.connect(mig_db)
    mig_conn.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            "key" TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'unused',
            expire_at TEXT NOT NULL,
            bound_machine TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            token TEXT UNIQUE NOT NULL,
            machine_code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
    """)
    mig_conn.execute(
        "INSERT INTO activations (license_key, token, machine_code, created_at, last_seen)"
        " VALUES (?, ?, ?, ?, ?)",
        ("VIP-ABCDEFGH-JKLMNPQR-STUVWXYZ", "oldrawtoken123456789012345678901234",
         "OLD-MC", "2026-11-17T00:00:00Z", "2026-11-17T00:00:00Z"),
    )
    mig_conn.commit()
    mig_conn.close()

    proc = subprocess.run(
        [sys.executable, "-c", "import main; main.init_db()"],
        env={**os.environ, "DB_PATH": mig_db},
        cwd=os.path.dirname(os.path.abspath(__file__)),
        capture_output=True, timeout=60,
    )
    check("迁移脚本执行成功", proc.returncode == 0, proc.stderr.decode("utf-8", errors="replace")[-300:])
    mig_conn = sqlite3.connect(mig_db)
    cols = [r[1] for r in mig_conn.execute("PRAGMA table_info(activations)")]
    rows = mig_conn.execute("SELECT token_hash FROM activations").fetchall()
    mig_conn.close()
    check("迁移后列为 token_hash", "token_hash" in cols and "token" not in cols, str(cols))
    check("旧 token 哈希值正确",
          bool(rows) and rows[0][0] == hash_token("oldrawtoken123456789012345678901234"), str(rows))
    os.remove(mig_db)

    print(f"\n结果：PASS={passed} FAIL={failed}")
    if failures:
        for f in failures:
            print("  - " + f)
        sys.exit(1)


def stage_spoof() -> None:
    """TRUST_PROXY=0 时伪造 X-Forwarded-For 不能绕过 IP 限流（需重启后执行）。"""
    if TRUST_PROXY:
        print("  [SKIP] TRUST_PROXY=1 环境，伪造 XFF 本就会被采信为反代追加地址，跳过")
        return
    print("== XFF 伪造不生效（TRUST_PROXY=0）==")
    codes = []
    for _ in range(32):
        st, b = call("/verify", {"token": "S" * 43, "machine_code": "spoof-machine"},
                     headers={"X-Forwarded-For": "1.2.3.4"})
        codes.append(st)
    print("  状态码序列:", codes)
    check("伪造 XFF 不会绕过限流：前 30 次正常", all(c == 200 for c in codes[:30]), str(codes[:30]))
    check("第 31、32 次仍按真实 IP 限流", codes[30] == 429 and codes[31] == 429, str(codes[30:]))
    print(f"\n结果：PASS={passed} FAIL={failed}")
    if failures:
        for f in failures:
            print("  - " + f)
        sys.exit(1)


def _audit_path() -> str:
    return os.environ.get("AUDIT_LOG_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(DB_PATH)) or ".", "audit.jsonl")


def _audit_contains(event: str) -> bool:
    path = _audit_path()
    try:
        with open(path, encoding="utf-8") as f:
            return f'"{event}"' in f.read()
    except OSError:
        return False


def stage_rebind() -> None:
    """v1.3.0 改绑策略：宽限期内改绑 / 过期拒绝 / 管理员改绑与解绑 / 批次吊销 / 审计。"""
    print("== 1. 宽限期内改绑（首发后 24h 内换机器）==")
    key = admin_gen_keys(1, 30)[0]
    st, b1 = call("/activate", {"key": key, "machine_code": "GRACE-A"})
    tok1 = (b1.get("data") or {}).get("token")
    check("首次激活成功", st == 200 and b1.get("code") == 0, f"{st} {b1}")

    st, b2 = call("/activate", {"key": key, "machine_code": "GRACE-B"})
    tok2 = (b2.get("data") or {}).get("token")
    check("宽限期内换机器改绑成功", st == 200 and b2.get("code") == 0, f"{st} {b2}")
    rows = db_rows('SELECT bound_machine FROM licenses WHERE "key" = ?', (key,))
    check("绑定已更新为 GRACE-B", bool(rows) and rows[0][0] == "GRACE-B", str(rows))
    if tok1 and tok2:
        st, v1 = call("/verify", {"token": tok1, "machine_code": "GRACE-A"})
        st2, v2 = call("/verify", {"token": tok2, "machine_code": "GRACE-B"})
        check("改绑后旧 token 失效（旧机器无法继续使用）", v1.get("code") == 1, f"{v1}")
        check("改绑后新 token 有效", v2.get("code") == 0, f"{v2}")

    print("== 2. 宽限期已过：改绑被拒 ==")
    conn = sqlite3.connect(DB_PATH)
    conn.execute('UPDATE licenses SET bound_at = ? WHERE "key" = ?',
                 ("2000-01-01T00:00:00Z", key))
    conn.commit()
    conn.close()
    st, b3 = call("/activate", {"key": key, "machine_code": "GRACE-C"})
    check("宽限期已过换机器被拒", st == 200 and b3.get("code") == 1 and b3.get("msg") == "卡密无效或已失效", f"{st} {b3}")

    print("== 3. 管理员改绑 / 解绑 ==")
    expect("管理员改绑到指定机器", "/admin/rebind",
           {"key": key, "machine_code": "GRACE-ADMIN"}, 200, 0, "改绑成功",
           headers={"X-Admin-Key": ADMIN_KEY})
    st, b4 = call("/activate", {"key": key, "machine_code": "GRACE-ADMIN"})
    check("改绑后原机器可直接激活", st == 200 and b4.get("code") == 0, f"{st} {b4}")
    expect("管理员解绑", "/admin/rebind", {"key": key}, 200, 0, "改绑成功",
           headers={"X-Admin-Key": ADMIN_KEY})
    st, b5 = call("/activate", {"key": key, "machine_code": "GRACE-ANY"})
    check("解绑后可绑定任意机器", st == 200 and b5.get("code") == 0, f"{st} {b5}")
    expect("改绑缺少管理员密钥 -> 403", "/admin/rebind",
           {"key": key, "machine_code": "X"}, 403, 1, "无权限访问")
    expect("改绑不存在的卡密", "/admin/rebind",
           {"key": "VIP-AAAAAAAA-BBBBBBBB-CCCCCCCC", "machine_code": "X"}, 200, 1, "卡密不存在",
           headers={"X-Admin-Key": ADMIN_KEY})

    print("== 4. 批次号与批量吊销 ==")
    st, gb = call("/admin/gen_keys", {"count": 3, "expire_days": 30, "batch": "TESTBATCH-V13"},
                  {"X-Admin-Key": ADMIN_KEY})
    keys = (gb.get("data") or {}).get("keys") or []
    check("批量生成成功", st == 200 and gb.get("code") == 0 and len(keys) == 3, f"{st} {gb}")
    check("响应携带批次号", (gb.get("data") or {}).get("batch") == "TESTBATCH-V13", str(gb))
    rows = db_rows("SELECT COUNT(*) FROM licenses WHERE batch = ?", ("TESTBATCH-V13",))
    check("批次号已入库", bool(rows) and rows[0][0] == 3, str(rows))
    st, rb = call("/admin/revoke_batch", {"batch": "TESTBATCH-V13"}, {"X-Admin-Key": ADMIN_KEY})
    check("批量吊销成功（3 张未使用）", st == 200 and rb.get("code") == 0
          and (rb.get("data") or {}).get("revoked_count") == 3, f"{st} {rb}")
    st, ba = call("/activate", {"key": keys[0], "machine_code": "BATCH-M"})
    check("吊销后批次内卡密无法激活", st == 200 and ba.get("code") == 1 and ba.get("msg") == "卡密无效或已失效", f"{st} {ba}")
    expect("批量吊销非法批次号", "/admin/revoke_batch", {"batch": "bad batch!"}, 200, 1, "批次号格式",
           headers={"X-Admin-Key": ADMIN_KEY})
    expect("批量吊销缺少管理员密钥 -> 403", "/admin/revoke_batch", {"batch": "X"}, 403, 1, "无权限访问")

    print("== 5. 审计日志 ==")
    check("审计文件已生成", os.path.exists(_audit_path()), _audit_path())
    for event in ("gen_keys", "revoke_batch", "rebind"):
        check(f"审计包含事件 {event}", _audit_contains(event), _audit_path())
    # 若配置了 ADMIN_ALLOW_IPS 且当前 IP 不在白名单，鉴权失败也会写审计；默认不配置则跳过

    print(f"\n结果：PASS={passed} FAIL={failed}")
    if failures:
        for f in failures:
            print("  - " + f)
        sys.exit(1)


if __name__ == "__main__":
    stage = (sys.argv[1] if len(sys.argv) > 1 else "func").lower()
    stages = {
        "func": stage_func, "mc": stage_mc, "ip": stage_ip, "escape": stage_escape,
        "race": stage_race, "sig": stage_sig, "security": stage_security, "spoof": stage_spoof,
        "rebind": stage_rebind,
    }
    if stage not in stages:
        print(f"未知阶段：{stage}，可选：{', '.join(stages)}")
        sys.exit(2)
    stages[stage]()
    print(f"ALL DONE ({stage})")

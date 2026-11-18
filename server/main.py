#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CheckPoint 验证服务 —— 单文件实现（安全加固版 v1.3.0）

包含：
  - 用户注册 / 登录（bcrypt rounds=12）
  - 卡密激活 / Token 验证（secrets.token_urlsafe(32)，入库前 SHA-256 哈希）
  - 管理员卡密生成 / 撤销（X-Admin-Key + 环境变量 ADMIN_KEY）
  - 限流（同 IP 30 次/分钟，同 machine_code 10 次激活/分钟，
          同「用户名+IP」8 次登录失败/分钟）
  - SQLite 参数化查询 + token 哈希存储 + token 滑动过期
  - 同机器码可重新激活（找回 token），异机器码拒绝
  - 响应签名（ECDSA P-256 / SHA-256，头 X-Signature）+ 请求 nonce 回显
    —— 客户端可验证响应确实来自持有私钥的正版服务端，防伪造服务器/MITM/重放
  - 安全响应头、请求体大小上限、请求体读取超时
  - 生产构建关闭 /docs /redoc /openapi.json

环境变量：
  DB_PATH          数据库文件路径，默认 /data/checkpoint.db
  ADMIN_KEY        管理员密钥，未设置则管理员接口一律 403（建议 >= 32 字符）
  SIGN_PRIVATE_KEY 响应签名私钥（PKCS#8 DER 的 base64 单行）；
                   未设置时所有响应均不签名（新版客户端会拒绝 code=0 响应）
  TRUST_PROXY      设为 1 时信任反向代理追加的 X-Forwarded-For 的【最右侧】地址
                   （仅反代后面开启；XFF 左侧值可被客户端伪造，永不采信）
  TOKEN_TTL_DAYS   token 滑动有效期（自 last_seen 起），默认 30 天
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import deque
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

import bcrypt
from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 新建文件（数据库/WAL）仅属主可读写，防止同机其他用户读取凭据
os.umask(0o077)

try:  # cryptography 仅用于响应签名；缺失时服务可用但响应不签名（启动时有警告）
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover - 依赖缺失兜底
    _CRYPTO_AVAILABLE = False

# --------------------------------------------------------------------------- #
# 常量与配置
# --------------------------------------------------------------------------- #

DB_PATH: str = os.environ.get("DB_PATH", "/data/checkpoint.db")
ADMIN_KEY: str = os.environ.get("ADMIN_KEY", "")
TRUST_PROXY: bool = os.environ.get("TRUST_PROXY", "0") == "1"

try:
    TOKEN_TTL_DAYS: int = int(os.environ.get("TOKEN_TTL_DAYS", "30"))
except ValueError:
    TOKEN_TTL_DAYS = 30
TOKEN_TTL_DAYS = max(1, min(TOKEN_TTL_DAYS, 3650))

# v1.3.0 业务/运维开关
REGISTER_ENABLED: bool = os.environ.get("REGISTER_ENABLED", "1") != "0"
# 管理员接口 IP 白名单（逗号分隔；为空=不限制。生产强烈建议配置）
ADMIN_ALLOW_IPS: Tuple[str, ...] = tuple(
    ip.strip() for ip in os.environ.get("ADMIN_ALLOW_IPS", "").split(",") if ip.strip()
)
# 最低客户端版本（需客户端发送 X-Client-Version；为空=不强制）
MIN_CLIENT_VERSION: str = os.environ.get("MIN_CLIENT_VERSION", "").strip()
# 首次激活后允许改绑（换机器）的宽限小时数；0 = 禁止改绑（仅管理员可处理）
try:
    REBIND_GRACE_HOURS: int = int(os.environ.get("REBIND_GRACE_HOURS", "24"))
except ValueError:
    REBIND_GRACE_HOURS = 24
REBIND_GRACE_HOURS = max(0, min(REBIND_GRACE_HOURS, 24 * 30))
# 审计日志（JSONL，追加写；为空则使用数据库同目录 audit.jsonl）
AUDIT_LOG_PATH: str = os.environ.get("AUDIT_LOG_PATH", "").strip() or os.path.join(
    os.path.dirname(os.path.abspath(DB_PATH)) or ".", "audit.jsonl"
)
AUDIT_MAX_BYTES = 20 * 1024 * 1024  # 单文件 20MB 后轮转为 .1（保留一代）

BCRYPT_ROUNDS: int = 12

# 用户名：3-32 位，字母/数字/下划线
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
# 卡密：VIP-XXXXXXXX-XXXXXXXX-XXXXXXXX，字符集排除 I / O / 0 / 1
KEY_RE = re.compile(r"^VIP-[A-HJ-NP-Z2-9]{8}-[A-HJ-NP-Z2-9]{8}-[A-HJ-NP-Z2-9]{8}$")
# token：URL-safe base64 字符集（入参仍是原始 token，入库前哈希）
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
# 请求 nonce（客户端每次请求随机生成，响应原样回显并纳入签名）
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
# 客户端 IP 的宽松形态（IPv4 / IPv6 字符集），不合法则忽略
IP_TOKEN_RE = re.compile(r"^[0-9A-Fa-f:.]{1,45}$")

# 卡密字符集（大写字母 + 数字，排除易混淆字符 I / O / 0 / 1）
KEY_CHARSET: str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

USERNAME_MIN, USERNAME_MAX = 3, 32
PASSWORD_MIN, PASSWORD_MAX = 8, 64
PASSWORD_MAX_BYTES = 72          # bcrypt 硬限制：超过 72 字节会被静默截断
MACHINE_CODE_MAX = 128
KEY_COUNT_MIN, KEY_COUNT_MAX = 1, 100
EXPIRE_DAYS_MIN, EXPIRE_DAYS_MAX = 1, 3650

def _env_int(name: str, default: int, lo: int = 1, hi: int = 1_000_000) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(lo, min(hi, value))


# 限流参数支持环境变量覆盖（负载测试/特殊部署用；默认值与文档一致）
IP_LIMIT_PER_MINUTE = _env_int("RATE_IP_LIMIT", 30)
ACTIVATE_LIMIT_PER_MINUTE = _env_int("RATE_ACTIVATE_LIMIT", 10)
LOGIN_FAIL_LIMIT_PER_MINUTE = _env_int("RATE_LOGIN_FAIL_LIMIT", 8)
RATE_WINDOW_SECONDS = 60.0

MAX_BODY_BYTES = 16 * 1024       # 请求体上限：16KB（本服务最大合法请求约 350B）
BODY_RECV_TIMEOUT = 5.0          # 单次 receive 等待上限（秒）：客户端停发数据 5s 即断
BODY_TOTAL_TIMEOUT = 15.0        # 请求体读取总时长上限（秒）：防 slow-drip 每秒喂 1 字节无限挂连接

HEALTH_PATH = "/health"
ACTIVATE_PATH = "/activate"
# 受「最低客户端版本」约束的业务路径（/admin/* 用管理员密钥鉴权，不受版本门槛限制）
BUSINESS_PATHS = ("/register", "/login", "/activate", "/verify")

# 统一错误文案（不区分“卡密不存在”与“卡密已用”）
MSG_KEY_INVALID = "卡密无效或已失效"
MSG_VERIFY_FAILED = "验证失败"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("checkpoint")

# 安全响应头：所有响应（含中间件生成的 4xx）统一携带
SECURITY_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
)


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #

def utcnow() -> datetime:
    """当前 UTC 时间（带时区）。"""
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    """统一为定长 ISO8601 UTC 字符串，便于直接用字符串比较先后。"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _s(value: Any, maxlen: int = 128) -> str:
    """日志脱敏：repr 转义控制字符/换行（防日志注入）并截断。"""
    try:
        return repr(value)[:maxlen]
    except Exception:  # pragma: no cover
        return "<unprintable>"


def clean_machine_code(raw: Optional[str]) -> Optional[str]:
    """
    机器码入库前的清洗：去除控制字符、首尾空白，并做长度截断。
    格式本身由客户端保证，服务端不做格式校验（红线 10）。
    """
    if not isinstance(raw, str):
        return None
    # 去掉除不可控字符外的控制字符（保留可打印 ASCII 与中文）
    cleaned = "".join(ch for ch in raw if ch.isprintable()).strip()
    if not cleaned:
        return None
    return cleaned[:MACHINE_CODE_MAX]


def safe_compare(a: str, b: str) -> bool:
    """常量时间比较（UTF-8 字节）；任一侧无法编码则直接 False，不退化为 ==。"""
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except (UnicodeEncodeError, AttributeError):
        return False


def hash_token(token: str) -> str:
    """token 入库前做 SHA-256：数据库失窃时攻击者拿不到可直接使用的 token。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _purge_stale_tokens() -> int:
    """
    清理超过滑动有效期的 token 行（v1.2.0）。
    v1.1.0 只在 verify 撞到旧行时懒清理，无人 verify 的行会无限累积
    （攻击者可反复重新激活刷行，实测 activations 表无限膨胀）。
    现在在启动时与每次激活/登录时主动清理，last_seen 有索引支撑。
    """
    cutoff = to_iso(utcnow() - timedelta(days=TOKEN_TTL_DAYS))
    with db() as conn:
        cur = conn.execute("DELETE FROM activations WHERE last_seen <= ?", (cutoff,))
        return cur.rowcount


def audit(event: str, **fields: Any) -> None:
    """
    追加审计事件到 JSONL（v1.3.0）：管理员生成/撤销/改绑、批量吊销、限流触发等。
    写失败不影响业务（仅告警日志），20MB 轮转一代（audit.jsonl.1）。
    生产建议用 log shipper（filebeat/vector）把该文件送到独立日志系统。
    """
    try:
        if os.path.exists(AUDIT_LOG_PATH) and os.path.getsize(AUDIT_LOG_PATH) > AUDIT_MAX_BYTES:
            try:
                os.replace(AUDIT_LOG_PATH, AUDIT_LOG_PATH + ".1")
            except OSError:
                pass
        record = {"ts": to_iso(utcnow()), "event": event, **fields}
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:  # pragma: no cover - 审计写失败不影响业务
        logger.warning("审计日志写入失败：%s", _s(repr(exc), 120))


def _version_tuple(value: str) -> Optional[Tuple[int, ...]]:
    """解析 'x.y.z' 为元组；非法返回 None。"""
    parts = value.strip().split(".")
    if not 1 <= len(parts) <= 4:
        return None
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _client_version_ok(scope: Dict[str, Any]) -> bool:
    """MIN_CLIENT_VERSION 未配置时恒 True；配置后要求 X-Client-Version >= 该值。"""
    if not MIN_CLIENT_VERSION:
        return True
    expected = _version_tuple(MIN_CLIENT_VERSION)
    if expected is None:  # 配置非法则放行（并在启动时告警）
        return True
    raw = ""
    for name, value in scope.get("headers") or []:
        if name == b"x-client-version":
            try:
                raw = value.decode("latin-1").strip()
            except Exception:  # pragma: no cover
                raw = ""
            break
    actual = _version_tuple(raw)
    if actual is None:
        return False
    # 补齐长度后按位比较（1.3 == 1.3.0）
    n = max(len(actual), len(expected))
    a = actual + (0,) * (n - len(actual))
    e = expected + (0,) * (n - len(expected))
    return a >= e


def _within_rebind_grace(bound_at: Optional[str]) -> bool:
    """首次绑定后的宽限期内允许改绑（缓解卡密被抢先绑定的问题）。"""
    if REBIND_GRACE_HOURS <= 0 or not bound_at:
        return False
    try:
        bound_dt = datetime.strptime(bound_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return utcnow() - bound_dt <= timedelta(hours=REBIND_GRACE_HOURS)


def ok(msg: str, data: Any = None, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"code": 0, "msg": msg, "data": data},
    )


def fail(msg: str, status_code: int = 200, headers: Optional[Dict[str, str]] = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"code": 1, "msg": msg, "data": None},
        headers=headers,
    )


# 登录失败时也消耗一次 bcrypt 校验，避免通过响应时间枚举用户名
_DUMMY_HASH: Optional[bytes] = None
_DUMMY_LOCK = threading.Lock()


def dummy_hash() -> bytes:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        with _DUMMY_LOCK:
            if _DUMMY_HASH is None:
                _DUMMY_HASH = bcrypt.hashpw(
                    b"checkpoint-dummy-password-for-timing", bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
                )
    return _DUMMY_HASH


def hash_password(password: str) -> str:
    """bcrypt 哈希，rounds=12，返回 ASCII 字符串便于存 TEXT 列。"""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
    return hashed.decode("ascii")


def check_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError):
        return False


def generate_key() -> str:
    """生成 VIP-XXXXXXXX-XXXXXXXX-XXXXXXXX 格式卡密（24 位随机字符）。"""
    blocks = [
        "".join(secrets.choice(KEY_CHARSET) for _ in range(8))
        for _ in range(3)
    ]
    return "VIP-" + "-".join(blocks)


def validate_password(password: str) -> Optional[str]:
    """返回中文错误提示，None 表示通过。"""
    if len(password) < PASSWORD_MIN or len(password) > PASSWORD_MAX:
        return f"密码长度必须为 {PASSWORD_MIN}-{PASSWORD_MAX} 位"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in password):
        # 控制字符（含 NUL）会导致 bcrypt 异常/静默截断，且没有任何正当用途
        return "密码包含非法控制字符"
    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError:
        # JSON 解析允许出现孤立代理对（\ud800 等），无法编码直接拒绝，避免 500
        return "密码包含非法字符"
    if len(encoded) > PASSWORD_MAX_BYTES:
        return "密码过长（UTF-8 编码后不得超过 72 字节）"
    return None


# --------------------------------------------------------------------------- #
# 响应签名（ECDSA P-256 / SHA-256）
# --------------------------------------------------------------------------- #

_SIGN_KEY: Any = None
_SIGN_KEY_LOADED = False
_SIGN_LOCK = threading.Lock()


def _load_sign_key():
    """从环境变量加载 PKCS#8 DER base64 私钥；缺失/非法时签名关闭。"""
    global _SIGN_KEY, _SIGN_KEY_LOADED
    if _SIGN_KEY_LOADED:
        return _SIGN_KEY
    with _SIGN_LOCK:
        if _SIGN_KEY_LOADED:
            return _SIGN_KEY
        raw = os.environ.get("SIGN_PRIVATE_KEY", "").strip()
        if raw and _CRYPTO_AVAILABLE:
            try:
                _SIGN_KEY = _serialization.load_der_private_key(base64.b64decode(raw), password=None)
                logger.info("响应签名已启用（ECDSA P-256）")
            except Exception:
                _SIGN_KEY = None
                logger.error("SIGN_PRIVATE_KEY 解析失败，响应签名未启用！")
        else:
            if not raw:
                logger.warning("未设置 SIGN_PRIVATE_KEY，响应签名未启用——新版客户端将拒绝未签名的成功响应")
            elif not _CRYPTO_AVAILABLE:
                logger.warning("未安装 cryptography，响应签名未启用")
        _SIGN_KEY_LOADED = True
        return _SIGN_KEY


def sign_response(raw: bytes) -> Optional[str]:
    """对最终响应字节签名，返回 base64(DER) 或 None（未启用）。"""
    key = _load_sign_key()
    if key is None:
        return None
    signature = key.sign(raw, _ec.ECDSA(_hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


# --------------------------------------------------------------------------- #
# 数据库
# --------------------------------------------------------------------------- #

SCHEMA_STATEMENTS: Tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT    UNIQUE NOT NULL,
        password_hash TEXT    NOT NULL,
        created_at    TEXT    NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS licenses (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        "key"         TEXT    UNIQUE NOT NULL,
        status        TEXT    NOT NULL DEFAULT 'unused',
        expire_at     TEXT    NOT NULL,
        bound_machine TEXT,
        bound_at      TEXT,
        batch         TEXT,
        created_at    TEXT    NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS activations (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER,
        license_key  TEXT,
        token_hash   TEXT UNIQUE NOT NULL,
        machine_code TEXT    NOT NULL,
        created_at   TEXT    NOT NULL,
        last_seen    TEXT    NOT NULL
    )
    """,
    'CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status)',
    'CREATE INDEX IF NOT EXISTS idx_licenses_batch ON licenses(batch)',
    'CREATE INDEX IF NOT EXISTS idx_activations_machine ON activations(machine_code)',
    'CREATE INDEX IF NOT EXISTS idx_activations_license ON activations(license_key)',
    'CREATE INDEX IF NOT EXISTS idx_activations_token ON activations(token_hash)',
    'CREATE INDEX IF NOT EXISTS idx_activations_last_seen ON activations(last_seen)',
    'CREATE INDEX IF NOT EXISTS idx_activations_user ON activations(user_id)',
)

# v1.1.0 → v1.2.0 → v1.3.0 的增量列（老库缺列时 ALTER TABLE 补齐）
_ADDED_COLUMNS: Tuple[Tuple[str, str, str], ...] = (
    ("licenses", "bound_at", "TEXT"),
    ("licenses", "batch", "TEXT"),
    ("activations", "user_id", "INTEGER"),
)

# 旧版（v1.0.0）activations 表结构：明文 token 列
_OLD_ACTIVATIONS_COLUMNS = ("id", "license_key", "token", "machine_code", "created_at", "last_seen")


def db_directory() -> str:
    directory = os.path.dirname(os.path.abspath(DB_PATH))
    return directory or "."


def connect() -> sqlite3.Connection:
    """每次请求新建连接：autocommit 模式，事务由 transaction() 显式控制。"""
    conn = sqlite3.connect(DB_PATH, timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextmanager
def db() -> Iterable[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction() -> Iterable[sqlite3.Connection]:
    """BEGIN IMMEDIATE：写事务一开始就取排他锁，防止并发重复激活。"""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        conn.execute("COMMIT")
    finally:
        conn.close()


def _migrate_activations_token_hash(conn: sqlite3.Connection) -> None:
    """旧库迁移：明文 token 列 → token_hash（SHA-256），原 token 依旧可用。"""
    cols = [row[1] for row in conn.execute("PRAGMA table_info(activations)")]
    if not cols or "token_hash" in cols or "token" not in cols:
        return
    logger.warning("检测到旧版 activations 表（明文 token 列），开始迁移为 SHA-256 哈希存储")
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            CREATE TABLE activations_new (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key  TEXT,
                token_hash   TEXT UNIQUE NOT NULL,
                machine_code TEXT    NOT NULL,
                created_at   TEXT    NOT NULL,
                last_seen    TEXT    NOT NULL
            )
            """
        )
        rows = conn.execute(
            "SELECT id, license_key, token, machine_code, created_at, last_seen FROM activations"
        ).fetchall()
        for row in rows:
            conn.execute(
                "INSERT INTO activations_new VALUES (?, ?, ?, ?, ?, ?)",
                (row["id"], row["license_key"], hash_token(row["token"]),
                 row["machine_code"], row["created_at"], row["last_seen"]),
            )
        conn.execute("DROP TABLE activations")
        conn.execute("ALTER TABLE activations_new RENAME TO activations")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_activations_machine ON activations(machine_code)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_activations_license ON activations(license_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_activations_token ON activations(token_hash)")
        conn.execute("COMMIT")
        logger.warning("迁移完成：%d 条激活记录的 token 已哈希化，原 token 继续有效", len(rows))
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise


def _migrate_added_columns(conn: sqlite3.Connection) -> None:
    """v1.3.0 增量列迁移：老库缺少 user_id / bound_at / batch 时补齐（幂等）。"""
    for table, column, coltype in _ADDED_COLUMNS:
        cols = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
        if not cols:
            continue
        if column not in cols:
            logger.info("迁移：为 %s 表增加列 %s", table, column)
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def init_db() -> None:
    directory = db_directory()
    os.makedirs(directory, exist_ok=True)
    with db() as conn:
        _migrate_activations_token_hash(conn)
        _migrate_added_columns(conn)
        for statement in SCHEMA_STATEMENTS:
            conn.execute(statement)
    purged = _purge_stale_tokens()
    if purged:
        logger.info("启动清理：删除 %d 条过期 token 行", purged)
    logger.info("数据库就绪：%s", os.path.abspath(DB_PATH))


# --------------------------------------------------------------------------- #
# 限流：滑动窗口，线程安全
# --------------------------------------------------------------------------- #

class SlidingWindowLimiter:
    """在 window_seconds 内最多允许 max_requests 次，按 key 独立计数。"""

    def __init__(self, max_requests: int, window_seconds: float = RATE_WINDOW_SECONDS,
                 max_keys: int = 50_000) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: Optional[float] = None) -> bool:
        if not key:
            return True
        now = time.monotonic() if now is None else now
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None:
                bucket = deque()
                self._hits[key] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            if len(self._hits) > self.max_keys:
                self._prune(cutoff)
            return True

    def blocked(self, key: str) -> bool:
        """只查询不消耗（用于失败后补记前的预检）。"""
        if not key:
            return False
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return False
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            return len(bucket) >= self.max_requests

    def _prune(self, cutoff: float) -> None:
        """清理已完全过期的 key，避免内存无限增长（调用方已持锁）。"""
        stale = [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]
        for k in stale:
            self._hits.pop(k, None)
        logger.debug("限流表清理，剩余 %d 个 key", len(self._hits))


ip_limiter = SlidingWindowLimiter(IP_LIMIT_PER_MINUTE)
machine_limiter = SlidingWindowLimiter(ACTIVATE_LIMIT_PER_MINUTE)
login_fail_limiter = SlidingWindowLimiter(LOGIN_FAIL_LIMIT_PER_MINUTE)


# --------------------------------------------------------------------------- #
# 安全中间件（纯 ASGI，单层完成限流/请求体上限/nonce/签名/安全头）
# --------------------------------------------------------------------------- #

def _client_ip(scope: Dict[str, Any]) -> str:
    """
    取客户端 IP。
    TRUST_PROXY=1 时取 X-Forwarded-For 的【最右侧】地址——它由我们信任的反代追加，
    客户端伪造的值只会出现在左侧。取出的值必须通过 IP 形态校验，否则退回 TCP 对端。
    """
    client = scope.get("client")
    ip = client[0] if client else "unknown"
    if TRUST_PROXY:
        xff_values = [
            value for name, value in (scope.get("headers") or [])
            if name == b"x-forwarded-for"
        ]
        if xff_values:
            try:
                chain = ",".join(v.decode("latin-1") for v in xff_values)
            except Exception:  # pragma: no cover - 解码兜底
                chain = ""
            last = chain.split(",")[-1].strip() if chain else ""
            if last and IP_TOKEN_RE.match(last):
                ip = last
            elif last:
                logger.warning("丢弃非法 X-Forwarded-For 值：%s", _s(last, 64))
    return ip


async def _read_request_body(receive) -> Tuple[bytes, str]:
    """
    读取请求体：
    - 总量超过 MAX_BODY_BYTES 返回 "too_large"
    - 客户端停发数据超过 BODY_RECV_TIMEOUT 返回 "timeout"
    - 读取总时长超过 BODY_TOTAL_TIMEOUT 也返回 "timeout"
      （防 slow-drip：每秒喂 1 字节永不触发单次超时的攻击，v1.2.0 修复）
    """
    body = b""
    started = time.monotonic()
    while True:
        elapsed = time.monotonic() - started
        remaining = BODY_TOTAL_TIMEOUT - elapsed
        if remaining <= 0:
            return body, "timeout"
        try:
            message = await asyncio.wait_for(receive(), timeout=min(BODY_RECV_TIMEOUT, remaining))
        except asyncio.TimeoutError:
            return body, "timeout"
        msg_type = message.get("type")
        if msg_type == "http.disconnect":
            return body, "disconnect"
        chunk = message.get("body", b"") or b""
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            return body, "too_large"
        if not message.get("more_body", False):
            return body, "done"


def _extract_machine_code(body: bytes) -> Optional[str]:
    """从 /activate 请求体里取 machine_code，作为限流键；解析失败则不限流。"""
    payload = _parse_json_object(body)
    if payload is None:
        return None
    raw = payload.get("machine_code")
    if not isinstance(raw, str):
        return None
    cleaned = clean_machine_code(raw)
    return cleaned or None


def _parse_json_object(body: bytes) -> Optional[Dict[str, Any]]:
    if not body:
        return None
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return payload if isinstance(payload, dict) else None


def _extract_nonce(body: bytes) -> Optional[str]:
    """取请求体里的 nonce（仅接受 [A-Za-z0-9_-]{8,64}）。"""
    payload = _parse_json_object(body)
    if payload is None:
        return None
    nonce = payload.get("nonce")
    if isinstance(nonce, str) and NONCE_RE.match(nonce):
        return nonce
    return None


def _replay_receive(body: bytes):
    """把已读走的请求体回放给下游应用，只回放一次。"""
    state = {"done": False}

    async def receive():
        if not state["done"]:
            state["done"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


def _encode_headers(headers: List[Tuple[str, str]]) -> list:
    encoded = []
    for name, value in headers:
        try:
            encoded.append((name.encode("latin-1"), str(value).encode("latin-1")))
        except UnicodeEncodeError:  # pragma: no cover - 头值非法兜底
            encoded.append((name.encode("latin-1"), b""))
    return encoded


async def _send_raw(send, status_code: int, body: bytes,
                    headers: List[Tuple[str, str]]) -> None:
    all_headers = _encode_headers(headers)
    all_headers.append((b"content-length", str(len(body)).encode("ascii")))
    await send({"type": "http.response.start", "status": status_code, "headers": all_headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _send_json(send, status_code: int, payload: Dict[str, Any],
                     extra_headers: Optional[Dict[str, str]] = None) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = [("content-type", "application/json; charset=utf-8")]
    headers.extend(SECURITY_HEADERS)
    for name, value in (extra_headers or {}).items():
        headers.append((name, str(value)))
    await _send_raw(send, status_code, raw, headers)


class SecurityMiddleware:
    """
    1) 同 IP 每分钟最多 30 次（/health 除外）
    2) 同 machine_code 每分钟最多 10 次激活尝试（仅 /activate）
    3) 请求体上限 16KB（413），读取总超时 10s（408）
    4) 请求 nonce 回显进响应 JSON（顶层字段）
    5) 业务响应签名：ECDSA P-256/SHA-256 → X-Signature（/health 除外）
    6) 全部响应带安全响应头
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # ---- IP 限流（/health 除外） ----
        ip = _client_ip(scope)
        if path != HEALTH_PATH and not ip_limiter.allow(ip):
            logger.warning("IP 限流触发：%s %s", _s(ip, 64), _s(path, 64))
            await _send_json(
                send, 429,
                {"code": 1, "msg": "请求过于频繁，请稍后再试", "data": None},
                {"Retry-After": "60"},
            )
            return

        # ---- 请求体：上限 + 超时 ----
        body, state = await _read_request_body(receive)
        if state == "too_large":
            logger.warning("请求体超限：%s %s %d 字节", _s(ip, 64), _s(path, 64), len(body))
            await _send_json(send, 413, {"code": 1, "msg": "请求体过大", "data": None})
            return
        if state == "timeout":
            logger.warning("请求体读取超时：%s %s", _s(ip, 64), _s(path, 64))
            await _send_json(send, 408, {"code": 1, "msg": "请求超时", "data": None})
            return
        if state == "disconnect":
            return

        # ---- 最低客户端版本（v1.3.0，可选） ----
        if MIN_CLIENT_VERSION and path in BUSINESS_PATHS and not _client_version_ok(scope):
            logger.info("客户端版本过低被拒：%s", _s(path, 64))
            await _send_json(
                send, 426,
                {"code": 1, "msg": "客户端版本过低，请升级后使用", "data": None},
            )
            return

        # ---- machine_code 限流（仅 /activate） ----
        if path == ACTIVATE_PATH and scope.get("method") == "POST":
            machine_code = _extract_machine_code(body)
            if machine_code and not machine_limiter.allow(machine_code):
                logger.warning("machine_code 限流触发：%s", _s(machine_code))
                await _send_json(
                    send, 429,
                    {"code": 1, "msg": "激活尝试过于频繁，请稍后再试", "data": None},
                    {"Retry-After": "60"},
                )
                return

        nonce = _extract_nonce(body)
        response_status = {"value": 200}
        response_headers: List[Tuple[str, str]] = []
        response_chunks: List[bytes] = []

        async def send_wrapper(message) -> None:
            msg_type = message.get("type")
            if msg_type == "http.response.start":
                response_status["value"] = message.get("status", 200)
                raw_headers = message.get("headers") or []
                for name, value in raw_headers:
                    try:
                        response_headers.append(
                            (name.decode("latin-1"), value.decode("latin-1")))
                    except Exception:  # pragma: no cover
                        continue
                return  # 暂存 start，等 body 收齐再统一发送
            if msg_type == "http.response.body":
                response_chunks.append(message.get("body", b"") or b"")
                if message.get("more_body", False):
                    return

                raw = b"".join(response_chunks)
                headers = [("content-type", "application/json; charset=utf-8")]
                headers.extend(SECURITY_HEADERS)

                if path != HEALTH_PATH:
                    payload = _parse_json_object(raw)
                    if payload is not None:
                        if nonce is not None:
                            payload["nonce"] = nonce
                        try:
                            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                        except (ValueError, UnicodeEncodeError):  # pragma: no cover
                            raw = b"{}"
                        signature = sign_response(raw)
                        if signature:
                            headers.append(("X-Signature", signature))

                for name, value in response_headers:
                    if name.lower() in ("content-length", "content-type"):
                        continue
                    headers.append((name, value))
                await _send_raw(send, response_status["value"], raw, headers)
                return
            if msg_type == "http.disconnect":  # pragma: no cover
                return
            await send(message)  # pragma: no cover - 未知消息透传

        try:
            await self.app(scope, _replay_receive(body), send_wrapper)
        except sqlite3.OperationalError:
            # DB 锁竞争 / busy_timeout 耗尽等瞬态故障：优雅降级为 503，而非 500
            # （实测 30 并发写爆发不触发，但作为纵深保护保留）
            logger.warning("数据库瞬态繁忙，返回 503：%s", _s(path, 64))
            try:
                await _send_json(send, 503,
                                 {"code": 1, "msg": "服务繁忙，请稍后再试", "data": None},
                                 {"Retry-After": "5"})
            except Exception:  # pragma: no cover - 响应已开始时无法再发
                pass


# --------------------------------------------------------------------------- #
# 请求模型（必填/类型校验交给 pydantic，长度与格式在业务层给中文提示）
# --------------------------------------------------------------------------- #

class RegisterIn(BaseModel):
    username: str
    password: str


class LoginIn(BaseModel):
    username: str
    password: str


class ActivateIn(BaseModel):
    key: str
    machine_code: str


class VerifyIn(BaseModel):
    token: str
    machine_code: str


class GenKeysIn(BaseModel):
    count: int
    expire_days: int
    batch: Optional[str] = None


class RevokeIn(BaseModel):
    key: str


class RebindIn(BaseModel):
    key: str
    # None / 空字符串 = 解绑（下次激活可绑定任意机器）
    machine_code: Optional[str] = None


class RevokeBatchIn(BaseModel):
    batch: str


# --------------------------------------------------------------------------- #
# 应用
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if not ADMIN_KEY:
        logger.warning("未设置环境变量 ADMIN_KEY，管理员接口将一律返回 403")
    elif len(ADMIN_KEY) < 32:
        logger.warning("ADMIN_KEY 长度不足 32 字符，建议更换为更长的高熵密钥")
    if not REGISTER_ENABLED:
        logger.warning("开放注册已关闭（REGISTER_ENABLED=0）")
    if ADMIN_ALLOW_IPS:
        logger.info("管理员接口 IP 白名单已启用：%d 个地址", len(ADMIN_ALLOW_IPS))
    if MIN_CLIENT_VERSION:
        if _version_tuple(MIN_CLIENT_VERSION) is None:
            logger.warning("MIN_CLIENT_VERSION 非法（应为 x.y.z），版本门槛未生效")
        else:
            logger.info("最低客户端版本：%s", MIN_CLIENT_VERSION)
    if REBIND_GRACE_HOURS:
        logger.info("卡密改绑宽限期：%d 小时", REBIND_GRACE_HOURS)
    _load_sign_key()
    dummy_hash()  # 预热，避免首次登录失败时额外耗时
    yield


# 生产构建关闭交互式文档与 OpenAPI（避免向攻击者暴露接口全貌）
app = FastAPI(
    title="CheckPoint 验证服务",
    version="1.3.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(SecurityMiddleware)


@app.exception_handler(RequestValidationError)
async def on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # 只记录错误类型与字段位置，绝不记录 exc 里的原始输入值（可能含密码/卡密）
    safe_errors = [{"loc": e.get("loc"), "type": e.get("type")} for e in exc.errors()]
    logger.info("参数校验失败：%s %s", _s(request.url.path), safe_errors)
    return fail("请求参数缺失或类型不正确", status_code=422)


@app.exception_handler(Exception)
async def on_unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("未处理异常：%s", _s(request.url.path))
    return fail("服务内部错误", status_code=500)


@app.get("/health")
async def health() -> JSONResponse:
    """运维探针，不参与业务限流计数。"""
    return ok("服务正常", {"status": "ok"})


# ------------------------------- 注册 ------------------------------------ #

@app.post("/register")
async def register(payload: RegisterIn, request: Request) -> JSONResponse:
    if not REGISTER_ENABLED:
        # v1.3.0：生产可关闭开放注册（REGISTER_ENABLED=0），减少垃圾账号面
        return fail("注册功能未开放", status_code=403)

    username = payload.username.strip()
    password = payload.password

    if not USERNAME_RE.match(username):
        return fail(f"用户名必须为 {USERNAME_MIN}-{USERNAME_MAX} 位字母、数字或下划线")

    password_error = validate_password(password)
    if password_error:
        return fail(password_error)

    password_hash = hash_password(password)
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, to_iso(utcnow())),
            )
    except sqlite3.IntegrityError:
        return fail("用户名已存在")

    logger.info("新用户注册：%s", _s(username))
    return ok("注册成功")


# ------------------------------- 登录 ------------------------------------ #

@app.post("/login")
async def login(payload: LoginIn, request: Request) -> JSONResponse:
    username = payload.username.strip()
    password = payload.password

    if not USERNAME_RE.match(username):
        return fail(f"用户名必须为 {USERNAME_MIN}-{USERNAME_MAX} 位字母、数字或下划线")
    password_error = validate_password(password)
    if password_error:
        return fail(password_error)

    ip = _client_ip(request.scope)
    fail_key = f"{username}|{ip}"
    if login_fail_limiter.blocked(fail_key):
        logger.warning("登录失败限流触发：%s", _s(fail_key))
        return fail("登录尝试过于频繁，请稍后再试",
                    status_code=429, headers={"Retry-After": "60"})

    with db() as conn:
        row = conn.execute(
            'SELECT id, password_hash FROM users WHERE username = ?',
            (username,),
        ).fetchone()

    if row is None:
        check_password(password, dummy_hash().decode("ascii"))  # 时序对齐
        login_fail_limiter.allow(fail_key)  # 记一次失败（含对不存在用户名的爆破）
        return fail("用户名或密码错误")

    if not check_password(password, row["password_hash"]):
        login_fail_limiter.allow(fail_key)
        return fail("用户名或密码错误")

    token = secrets.token_urlsafe(32)
    now = to_iso(utcnow())
    with transaction() as conn:
        # v1.3.0 单会话：同一账号只保留最新一个登录 token（旧 token 立即失效），
        # 防止频繁登录把 activations 表刷爆（上一轮红队发现 F1 的遗留变种）
        deleted = conn.execute(
            "DELETE FROM activations WHERE user_id = ? AND license_key IS NULL",
            (row["id"],),
        ).rowcount
        conn.execute(
            "INSERT INTO activations (user_id, license_key, token_hash, machine_code, created_at, last_seen)"
            " VALUES (?, NULL, ?, '', ?, ?)",
            (row["id"], hash_token(token), now, now),
        )
    _purge_stale_tokens()  # 顺带清理过期 token 行（防表无限膨胀）
    if deleted:
        logger.info("单会话登录：注销用户 %s 的 %d 个旧登录 token", _s(username), deleted)

    logger.info("用户登录：%s", _s(username))
    return ok("登录成功", {"token": token})


# ------------------------------- 激活 ------------------------------------ #

class _ActivationRejected(Exception):
    """事务内用于触发回滚的内部控制流异常，不对外暴露。"""


@app.post("/activate")
async def activate(payload: ActivateIn) -> JSONResponse:
    raw_key = payload.key.strip().upper()
    if not KEY_RE.match(raw_key):
        return fail(MSG_KEY_INVALID)

    if len(payload.machine_code.strip()) > MACHINE_CODE_MAX:
        return fail(f"机器码长度不能超过 {MACHINE_CODE_MAX} 位")
    machine_code = clean_machine_code(payload.machine_code)
    if machine_code is None:
        return fail("机器码不能为空")

    now = to_iso(utcnow())
    token = secrets.token_urlsafe(32)

    try:
        with transaction() as conn:
            row = conn.execute(
                'SELECT "key", status, expire_at, bound_machine, bound_at FROM licenses WHERE "key" = ?',
                (raw_key,),
            ).fetchone()

            # 不存在 / 已撤销 / 已过期 —— 返回完全相同的文案
            if row is None or row["status"] == "revoked" or row["expire_at"] <= now:
                logger.info("激活失败（卡密不可用）：key 存在=%s", row is not None)
                raise _ActivationRejected

            if row["status"] == "unused":
                # 首次激活：抢占置为 used，并发下只有一个请求成功
                updated = conn.execute(
                    'UPDATE licenses SET status = ?, bound_machine = ?, bound_at = ?'
                    ' WHERE "key" = ? AND status = ?',
                    ("used", machine_code, now, raw_key, "unused"),
                )
                if updated.rowcount != 1:
                    raise _ActivationRejected
            elif row["status"] == "used":
                bound = row["bound_machine"] or ""
                if bound and safe_compare(bound, machine_code):
                    # 同机器重新激活（token 丢失/重装找回）：绑定不变，补发新 token
                    conn.execute(
                        'UPDATE licenses SET bound_at = ? WHERE "key" = ?',
                        (now, raw_key),
                    )
                elif not bound or _within_rebind_grace(row["bound_at"]):
                    # v1.3.0：管理员解绑（bound 为空）或首次绑定后的宽限期内允许改绑；
                    # 宽限期用于缓解「卡密先被抢绑」问题（默认 24h，可配置/可关闭）
                    conn.execute(
                        'UPDATE licenses SET bound_machine = ?, bound_at = ? WHERE "key" = ?',
                        (machine_code, now, raw_key),
                    )
                    # 改绑后注销该卡密此前签发的全部 token（旧机器立即失效）
                    conn.execute(
                        "DELETE FROM activations WHERE license_key = ? AND token_hash != ?",
                        (raw_key, hash_token(token)),
                    )
                    logger.warning("卡密改绑：%s -> machine_code=%s（宽限期/管理员解绑）",
                                   _mask_key(raw_key), _s(machine_code))
                    audit("rebind_grace", key=_mask_key(raw_key), machine_code=machine_code)
                else:
                    logger.info("激活失败（卡密已绑定其他机器，超过改绑宽限）")
                    raise _ActivationRejected
            else:
                raise _ActivationRejected

            conn.execute(
                "INSERT INTO activations (license_key, token_hash, machine_code, created_at, last_seen)"
                " VALUES (?, ?, ?, ?, ?)",
                (raw_key, hash_token(token), machine_code, now, now),
            )
    except _ActivationRejected:
        return fail(MSG_KEY_INVALID)

    _purge_stale_tokens()  # 顺带清理过期 token 行（防表无限膨胀）

    logger.info("激活成功：machine_code=%s", _s(machine_code))
    return ok("激活成功", {"token": token})


# ------------------------------- 验证 ------------------------------------ #

@app.post("/verify")
async def verify(payload: VerifyIn) -> JSONResponse:
    token = payload.token.strip()
    if not TOKEN_RE.match(token):
        return fail(MSG_VERIFY_FAILED)

    machine_code = clean_machine_code(payload.machine_code)
    if machine_code is None:
        return fail(MSG_VERIFY_FAILED)

    now = utcnow()
    now_iso = to_iso(now)
    cutoff_iso = to_iso(now - timedelta(days=TOKEN_TTL_DAYS))
    token_hash = hash_token(token)

    with db() as conn:
        row = conn.execute(
            "SELECT a.machine_code, a.license_key, a.last_seen, l.status, l.expire_at"
            " FROM activations AS a"
            ' LEFT JOIN licenses AS l ON l."key" = a.license_key'
            " WHERE a.token_hash = ?",
            (token_hash,),
        ).fetchone()

        if row is None:
            return fail(MSG_VERIFY_FAILED)

        # 滑动过期：所有 token（含登录 token）自 last_seen 起最多存活 TOKEN_TTL_DAYS 天
        if row["last_seen"] <= cutoff_iso:
            conn.execute("DELETE FROM activations WHERE token_hash = ?", (token_hash,))
            logger.info("验证失败：token 已过期（超过 %d 天未使用）", TOKEN_TTL_DAYS)
            return fail(MSG_VERIFY_FAILED)

        # 激活 token（license_key 非空）才比对机器码与卡密状态；登录 token 不绑定机器
        if row["license_key"] is not None:
            if not safe_compare(row["machine_code"], machine_code):
                logger.info("验证失败：机器码不匹配")
                return fail(MSG_VERIFY_FAILED)
            # 卡密被撤销 / 关联丢失 / 已过期：三者同样只返回统一文案
            if row["status"] != "used":
                logger.info("验证失败：卡密状态不可用（%s）", _s(row["status"], 16))
                return fail(MSG_VERIFY_FAILED)
            if row["expire_at"] is not None and row["expire_at"] <= now_iso:
                logger.info("验证失败：卡密已过期")
                return fail(MSG_VERIFY_FAILED)

        conn.execute(
            "UPDATE activations SET last_seen = ? WHERE token_hash = ?",
            (now_iso, token_hash),
        )

    return ok("验证通过", {"valid": True})


# --------------------------- 管理员：生成卡密 ----------------------------- #

BATCH_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


async def _require_admin(request: Request,
                         x_admin_key: Optional[str]) -> Optional[JSONResponse]:
    """鉴权 + 可选 IP 白名单（ADMIN_ALLOW_IPS）。通过返回 None，否则返回 403。"""
    if not ADMIN_KEY:
        return fail("管理员密钥未配置", status_code=403)
    if ADMIN_ALLOW_IPS:
        ip = _client_ip(request.scope)
        if ip not in ADMIN_ALLOW_IPS:
            logger.warning("管理员接口 IP 不在白名单：%s", _s(ip, 64))
            audit("admin_ip_denied", ip=ip)
            return fail("无权限访问", status_code=403)
    if not x_admin_key or not safe_compare(x_admin_key, ADMIN_KEY):
        logger.warning("管理员接口鉴权失败")
        audit("admin_auth_failed", ip=_client_ip(request.scope))
        return fail("无权限访问", status_code=403)
    return None


def _mask_key(key: str) -> str:
    """日志里只保留卡密前缀，不打印完整卡密。"""
    return key[:12] + "-****" if len(key) >= 12 else "****"


def _new_batch_id() -> str:
    return "B" + utcnow().strftime("%Y%m%d") + "-" + secrets.token_hex(3)


@app.post("/admin/gen_keys")
async def admin_gen_keys(
    payload: GenKeysIn,
    request: Request,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
) -> JSONResponse:
    denied = await _require_admin(request, x_admin_key)
    if denied is not None:
        return denied

    if payload.count < KEY_COUNT_MIN or payload.count > KEY_COUNT_MAX:
        return fail(f"生成数量必须为 {KEY_COUNT_MIN}-{KEY_COUNT_MAX}")
    if payload.expire_days < EXPIRE_DAYS_MIN or payload.expire_days > EXPIRE_DAYS_MAX:
        return fail(f"有效期天数必须为 {EXPIRE_DAYS_MIN}-{EXPIRE_DAYS_MAX}")

    batch = (payload.batch or "").strip() or _new_batch_id()
    if not BATCH_RE.match(batch):
        return fail("批次号格式不正确（1-64 位字母/数字/下划线/连字符）")

    created_at = to_iso(utcnow())
    expire_at = to_iso(utcnow() + timedelta(days=payload.expire_days))

    keys: List[str] = []
    with db() as conn:
        while len(keys) < payload.count:
            candidate = generate_key()
            inserted = conn.execute(
                'INSERT OR IGNORE INTO licenses ("key", status, expire_at, bound_machine, batch, created_at)'
                " VALUES (?, ?, ?, NULL, ?, ?)",
                (candidate, "unused", expire_at, batch, created_at),
            )
            if inserted.rowcount == 1:
                keys.append(candidate)
            # 冲突时继续下一轮（概率极低：32^24 空间）

    logger.info("管理员生成卡密 %d 个，有效期 %d 天，批次 %s",
                len(keys), payload.expire_days, _s(batch, 64))
    audit("gen_keys", count=len(keys), batch=batch,
          expire_days=payload.expire_days, ip=_client_ip(request.scope))
    return ok("生成成功", {"keys": keys, "batch": batch})


# --------------------------- 管理员：撤销卡密 ----------------------------- #

@app.post("/admin/revoke")
async def admin_revoke(
    payload: RevokeIn,
    request: Request,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
) -> JSONResponse:
    denied = await _require_admin(request, x_admin_key)
    if denied is not None:
        return denied

    raw_key = payload.key.strip().upper()
    if not KEY_RE.match(raw_key):
        return fail("卡密格式不正确")

    with db() as conn:
        updated = conn.execute(
            'UPDATE licenses SET status = ? WHERE "key" = ?',
            ("revoked", raw_key),
        )

    if updated.rowcount == 0:
        return fail("卡密不存在")

    logger.info("管理员撤销卡密：%s", _mask_key(raw_key))
    audit("revoke", key=_mask_key(raw_key), ip=_client_ip(request.scope))
    return ok("撤销成功", {"key": raw_key, "status": "revoked"})


# ------------------------ 管理员：批量吊销 / 改绑 -------------------------- #

@app.post("/admin/revoke_batch")
async def admin_revoke_batch(
    payload: RevokeBatchIn,
    request: Request,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
) -> JSONResponse:
    """按批次吊销所有【未使用】卡密（卡密泄露/分销事故的止损手段）。"""
    denied = await _require_admin(request, x_admin_key)
    if denied is not None:
        return denied

    batch = payload.batch.strip()
    if not BATCH_RE.match(batch):
        return fail("批次号格式不正确")

    with db() as conn:
        updated = conn.execute(
            'UPDATE licenses SET status = ? WHERE batch = ? AND status = ?',
            ("revoked", batch, "unused"),
        )

    logger.warning("管理员批量吊销：批次 %s 共 %d 张未使用卡密", _s(batch, 64), updated.rowcount)
    audit("revoke_batch", batch=batch, count=updated.rowcount, ip=_client_ip(request.scope))
    return ok("批量吊销成功", {"batch": batch, "revoked_count": updated.rowcount})


@app.post("/admin/rebind")
async def admin_rebind(
    payload: RebindIn,
    request: Request,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
) -> JSONResponse:
    """
    管理员改绑/解绑（客服场景：用户换机器、卡密被误绑）：
    - 指定 machine_code：直接把绑定改为该机器（旧 token 全部注销）
    - machine_code 为空/null：解绑，下一次激活可绑定任意机器
    """
    denied = await _require_admin(request, x_admin_key)
    if denied is not None:
        return denied

    raw_key = payload.key.strip().upper()
    if not KEY_RE.match(raw_key):
        return fail("卡密格式不正确")

    machine = None
    if payload.machine_code is not None:
        candidate = clean_machine_code(payload.machine_code)
        if candidate is None:
            return fail("机器码不能为空")
        if len(payload.machine_code.strip()) > MACHINE_CODE_MAX:
            return fail(f"机器码长度不能超过 {MACHINE_CODE_MAX} 位")
        machine = candidate

    now = to_iso(utcnow())
    with transaction() as conn:
        row = conn.execute(
            'SELECT "key", status FROM licenses WHERE "key" = ?', (raw_key,),
        ).fetchone()
        if row is None:
            return fail("卡密不存在")
        conn.execute(
            'UPDATE licenses SET bound_machine = ?, bound_at = ? WHERE "key" = ?',
            (machine, now, raw_key),
        )
        # 改绑/解绑统一注销旧 token，避免旧机器继续使用
        conn.execute("DELETE FROM activations WHERE license_key = ?", (raw_key,))

    logger.warning("管理员改绑卡密：%s -> machine_code=%s",
                   _mask_key(raw_key), _s(str(machine)))
    audit("rebind", key=_mask_key(raw_key), machine_code=machine,
          ip=_client_ip(request.scope))
    return ok("改绑成功", {"key": raw_key, "bound_machine": machine})


# --------------------------------------------------------------------------- #
# 本地调试入口
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        reload=False,
        limit_concurrency=100,
    )

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite 在线备份（v1.3.0）：sqlite3 backup API + 完整性校验 + gzip + 保留 14 份。
在容器内执行: python scripts/backup.py
输出 /data/backups/checkpoint-YYYYmmddTHHMMSSZ.db.gz 与一行 JSON 摘要。
"""
import gzip
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone

DB = os.environ.get("DB_PATH", "/data/checkpoint.db")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/data/backups")
KEEP = int(os.environ.get("BACKUP_KEEP", "14"))


def main():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tmp = tempfile.NamedTemporaryFile(prefix="ckpt-bak-", suffix=".db", delete=False)
    tmp.close()
    try:
        src = sqlite3.connect(DB, timeout=10)
        dst = sqlite3.connect(tmp.name)
        src.backup(dst)  # 在线备份（WAL 安全）
        dst.close()
        src.close()

        # 完整性校验
        check_conn = sqlite3.connect(tmp.name)
        integrity = check_conn.execute("PRAGMA integrity_check").fetchone()[0]
        counts = {}
        for table in ("users", "licenses", "activations"):
            try:
                counts[table] = check_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.Error:
                counts[table] = -1
        check_conn.close()
        if integrity != "ok":
            print(json.dumps({"result": "FAIL", "reason": f"integrity_check={integrity}"}))
            sys.exit(1)

        out = os.path.join(BACKUP_DIR, f"checkpoint-{ts}.db.gz")
        with open(tmp.name, "rb") as fin, gzip.open(out, "wb") as fout:
            fout.write(fin.read())
        size = os.path.getsize(out)

        # 保留最近 KEEP 份
        files = sorted(
            (os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR) if f.endswith(".db.gz")),
            key=os.path.getmtime,
        )
        removed = 0
        while len(files) > KEEP:
            os.remove(files.pop(0))
            removed += 1

        print(json.dumps({
            "result": "PASS", "file": out, "bytes": size,
            "integrity": integrity, "counts": counts, "removed_old": removed,
        }, ensure_ascii=False))
    finally:
        try:
            os.remove(tmp.name)
        except OSError:
            pass


if __name__ == "__main__":
    main()
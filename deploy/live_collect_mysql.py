#!/usr/bin/env python3
from __future__ import annotations
import os
import threading
from datetime import datetime
import pymysql
from live_collect_db import COL_ADD, COL_CNT, COL_EXT, COL_MOD, COL_VIEWER
_DDL = f"""
CREATE TABLE IF NOT EXISTS live_rooms (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    live_id VARCHAR(30) NOT NULL UNIQUE,
    user_id VARCHAR(20) NOT NULL DEFAULT 'admin',
    `{COL_VIEWER}` INT NULL,
    `{COL_ADD}` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `{COL_MOD}` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `{COL_EXT}` DATETIME NULL,
    `{COL_CNT}` INT NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""
class LiveCollectMySQL:
    def __init__(self, host=None, port=None, user=None, password=None, database=None):
        self.cfg = {
            "host": host or os.environ.get("MYSQL_HOST", "127.0.0.1"),
            "port": int(port or os.environ.get("MYSQL_PORT", "3306")),
            "user": user or os.environ.get("MYSQL_USER", "fdqc"),
            "password": password or os.environ.get("MYSQL_PASSWORD", ""),
            "database": database or os.environ.get("MYSQL_DATABASE", "dy_live"),
            "charset": "utf8mb4",
            "autocommit": False,
        }
        self.path = "mysql://%s@%s:%s/%s" % (self.cfg["user"], self.cfg["host"], self.cfg["port"], self.cfg["database"])
        self._lock = threading.Lock()
        self._init()
    def _connect(self):
        return pymysql.connect(**self.cfg)
    def _init(self):
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(_DDL)
                conn.commit()
            finally:
                conn.close()
    def upsert_rooms(self, rows, user_id="admin"):
        if not rows:
            return {"inserted": 0, "updated": 0, "total": self.count_unique()}
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        inserted = updated = 0
        seen = set()
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    for row in rows:
                        live_id = str(row.get("live_id") or row.get("room_id") or "").strip()
                        if not live_id or live_id in seen:
                            continue
                        seen.add(live_id)
                        uc = row.get("user_count")
                        try:
                            uc = int(uc) if uc is not None else None
                        except (TypeError, ValueError):
                            uc = None
                        cur.execute("SELECT Id FROM live_rooms WHERE live_id=%s", (live_id,))
                        if cur.fetchone():
                            cur.execute(f"UPDATE live_rooms SET `{COL_VIEWER}`=%s, `{COL_MOD}`=%s, `{COL_EXT}`=%s, `{COL_CNT}`=`{COL_CNT}`+1, user_id=%s WHERE live_id=%s", (uc, now, now, user_id, live_id))
                            updated += 1
                        else:
                            cur.execute(f"INSERT INTO live_rooms (live_id, user_id, `{COL_VIEWER}`, `{COL_ADD}`, `{COL_MOD}`, `{COL_EXT}`, `{COL_CNT}`) VALUES (%s,%s,%s,%s,%s,%s,1)", (live_id, user_id, uc, now, now, now))
                            inserted += 1
                    cur.execute("SELECT COUNT(*) FROM live_rooms")
                    total = int(cur.fetchone()[0])
                conn.commit()
            finally:
                conn.close()
        return {"inserted": inserted, "updated": updated, "total": total}
    def count_unique(self):
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM live_rooms")
                    row = cur.fetchone()
                    return int(row[0]) if row else 0
            finally:
                conn.close()
    def stats(self):
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM live_rooms")
                    total = int(cur.fetchone()[0])
                    cur.execute(f"SELECT COALESCE(SUM(`{COL_CNT}`),0) FROM live_rooms")
                    sum_extract = int(cur.fetchone()[0])
                return {"unique_rooms": total, "total_extractions": sum_extract, "db_path": self.path}
            finally:
                conn.close()
#!/usr/bin/env python3
"""SQLite storage for live room collection (db file under ./data/)."""
from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent


def resolve_db_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    try:
        import collect_runtime
        data_dir = collect_runtime.DATA_DIR
        if data_dir:
            return Path(data_dir) / "live_collect.db"
    except Exception:
        pass
    return Path(os.environ.get("COLLECT_DATA", str(APP_DIR / "data"))) / "live_collect.db"

COL_VIEWER = "房间人数"
COL_ADD = "添加时间"
COL_MOD = "修改时间"
COL_EXT = "提取时间"
COL_CNT = "提取次数"

_DDL = f"""
CREATE TABLE IF NOT EXISTS live_rooms (
    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
    live_id     VARCHAR(30) NOT NULL UNIQUE,
    user_id     VARCHAR(20) NOT NULL DEFAULT 'admin',
    {COL_VIEWER}    INTEGER,
    {COL_ADD}    TIMESTAMP NOT NULL DEFAULT (datetime('now', 'localtime')),
    {COL_MOD}    TIMESTAMP NOT NULL DEFAULT (datetime('now', 'localtime')),
    {COL_EXT}    DATETIME,
    {COL_CNT}    INTEGER NOT NULL DEFAULT 1
);
"""


class LiveCollectDB:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = resolve_db_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=60, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                cols = {r[1] for r in conn.execute("PRAGMA table_info(live_rooms)")}
                if not cols:
                    conn.executescript(_DDL)
                elif COL_VIEWER not in cols:
                    self._rebuild_table(conn)
                conn.commit()
            finally:
                conn.close()

    def _rebuild_table(self, conn: sqlite3.Connection) -> None:
        conn.execute("ALTER TABLE live_rooms RENAME TO live_rooms_old")
        conn.executescript(_DDL)
        old_cols = {r[1] for r in conn.execute("PRAGMA table_info(live_rooms_old)")}
        viewer_col = COL_VIEWER if COL_VIEWER in old_cols else next(
            (c for c in old_cols if c not in ("Id", "live_id", "user_id")), None
        )
        if viewer_col:
            conn.execute(
                f"INSERT OR IGNORE INTO live_rooms (live_id, user_id, {COL_VIEWER}, {COL_ADD}, "
                f"{COL_MOD}, {COL_EXT}, {COL_CNT}) "
                f"SELECT live_id, user_id, {viewer_col}, datetime('now','localtime'), "
                f"datetime('now','localtime'), datetime('now','localtime'), 1 FROM live_rooms_old"
            )
        else:
            conn.execute(
                f"INSERT OR IGNORE INTO live_rooms (live_id, user_id, {COL_ADD}, {COL_MOD}, {COL_EXT}, {COL_CNT}) "
                f"SELECT live_id, user_id, datetime('now','localtime'), "
                f"datetime('now','localtime'), datetime('now','localtime'), 1 FROM live_rooms_old"
            )
        conn.execute("DROP TABLE live_rooms_old")

    def upsert_rooms(self, rows: list[dict], user_id: str = "admin") -> dict:
        if not rows:
            return {"inserted": 0, "updated": 0, "total": self.count_unique()}
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        inserted = updated = 0
        seen: set[str] = set()
        with self._lock:
            conn = self._connect()
            try:
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
                    if conn.execute("SELECT Id FROM live_rooms WHERE live_id=?", (live_id,)).fetchone():
                        conn.execute(
                            f"UPDATE live_rooms SET {COL_VIEWER}=?, {COL_MOD}=?, {COL_EXT}=?, "
                            f"{COL_CNT}={COL_CNT}+1, user_id=? WHERE live_id=?",
                            (uc, now, now, user_id, live_id),
                        )
                        updated += 1
                    else:
                        conn.execute(
                            f"INSERT INTO live_rooms (live_id, user_id, {COL_VIEWER}, {COL_ADD}, "
                            f"{COL_MOD}, {COL_EXT}, {COL_CNT}) VALUES (?, ?, ?, ?, ?, ?, 1)",
                            (live_id, user_id, uc, now, now, now),
                        )
                        inserted += 1
                conn.commit()
                total = conn.execute("SELECT COUNT(*) AS n FROM live_rooms").fetchone()["n"]
            finally:
                conn.close()
        return {"inserted": inserted, "updated": updated, "total": int(total)}

    def count_unique(self) -> int:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT COUNT(*) AS n FROM live_rooms").fetchone()
                return int(row["n"]) if row else 0
            finally:
                conn.close()

    def stats(self) -> dict:
        with self._lock:
            conn = self._connect()
            try:
                total = conn.execute("SELECT COUNT(*) AS n FROM live_rooms").fetchone()["n"]
                sum_extract = conn.execute(
                    f"SELECT COALESCE(SUM({COL_CNT}),0) AS n FROM live_rooms"
                ).fetchone()["n"]
                return {
                    "unique_rooms": int(total),
                    "total_extractions": int(sum_extract),
                    "db_path": str(self.path),
                }
            finally:
                conn.close()

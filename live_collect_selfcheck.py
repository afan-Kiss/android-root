#!/usr/bin/env python3
"""Quick sanity check for live collect modules. Run: python live_collect_selfcheck.py"""
from __future__ import annotations
import ast
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SIGN = Path(__file__).resolve().parent  # scripts added below
for p in (ROOT, Path(r"E:\douyin-android-sign\scripts")):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

FILES = ("live_collect_db.py", "live_collect_server.py", "live_collect_client.py", "device_profile_pool.py")


def main() -> int:
    errs: list[str] = []
    for fn in FILES:
        p = ROOT / fn
        if not p.is_file():
            errs.append(f"missing {fn}")
            continue
        head = p.read_bytes()[:4]
        if head.startswith(b"#\x00"):
            errs.append(f"utf16 encoding: {fn}")
        try:
            ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError as e:
            errs.append(f"syntax {fn}: {e}")

    from live_collect_db import LiveCollectDB, COL_VIEWER
    tdb = Path(tempfile.mktemp(suffix=".db"))
    db = LiveCollectDB(tdb)
    cols = [r[1] for r in sqlite3.connect(tdb).execute("PRAGMA table_info(live_rooms)")]
    if COL_VIEWER not in cols:
        errs.append("db chinese columns missing")
    r = db.upsert_rooms([{"live_id": "chk1", "user_count": 1}, {"live_id": "chk1", "user_count": 2}])
    if r["inserted"] != 1 or r["updated"] != 0:
        errs.append(f"batch dedup broken: {r}")

    from device_profile_pool import profile_for_worker, template_count
    from profile_tools import load_json
    base_path = Path(r"E:\douyin-android-sign\config\device_profile.json")
    if not base_path.is_file():
        errs.append(f"base profile missing: {base_path}")
    else:
        base = load_json(base_path)
        lic = base["appRegisterConfig"][3]
        p = profile_for_worker(base, 1)
        if p["appRegisterConfig"][3] != lic:
            errs.append("license overwritten by profile pool")
        if "mssdkPrefs" in p or "deviceId" in p:
            errs.append("identity not stripped from worker profile")
        n = len({profile_for_worker(base, i)["build"]["model"] for i in range(1, 51)})
        if n < 10:
            errs.append(f"model diversity too low: {n}")

    if errs:
        print("FAILED:")
        for e in errs:
            print(" -", e)
        return 1
    print("OK: syntax, db, profile pool (%s templates, %s+ models/50w)" % (template_count(), n))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
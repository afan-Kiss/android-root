#!/usr/bin/env python3
from __future__ import annotations
import os
from pathlib import Path
from live_collect_db import LiveCollectDB, resolve_db_path
def make_store(db_path=None):
    backend = (os.environ.get("COLLECT_BACKEND") or "sqlite").strip().lower()
    if backend == "mysql":
        from live_collect_mysql import LiveCollectMySQL
        return LiveCollectMySQL()
    return LiveCollectDB(resolve_db_path(db_path))
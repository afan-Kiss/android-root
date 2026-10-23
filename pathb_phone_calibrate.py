#!/usr/bin/env python3
"""Delegate to authoritative phone calibrate script in douyin-android-sign."""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

_SCRIPT = Path(r"E:\douyin-android-sign\scripts\pathb_phone_calibrate.py")
sys.argv[0] = str(_SCRIPT)
raise SystemExit(runpy.run_path(str(_SCRIPT), run_name="__main__"))

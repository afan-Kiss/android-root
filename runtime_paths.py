#!/usr/bin/env python3
"""Initialize PYTHONPATH for device_register / pure_sign / live_audience."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
SIGN_ROOT = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))
SIGN_VENDOR = Path(os.environ.get("PURE_SIGN_VENDOR", ""))


def _vendor_dir() -> Path:
    if SIGN_VENDOR.is_dir():
        return SIGN_VENDOR
    bundled = APP_DIR.parent / "sign_vendor"
    if bundled.is_dir():
        return bundled
    return SIGN_ROOT / "tmp" / "sign-pack-original" / "dy_unified" / "vendor"


def init(extra: Path | None = None) -> None:
    vendor = _vendor_dir()
    os.environ.setdefault("DOUYIN_SIGN_ROOT", str(SIGN_ROOT))
    if vendor.is_dir():
        os.environ.setdefault("PURE_SIGN_VENDOR", str(vendor))
    for p in (extra, vendor, SIGN_ROOT / "scripts", APP_DIR):
        if p and p.is_dir():
            sp = str(p)
            if sp not in sys.path:
                sys.path.insert(0, sp)
    for d in (vendor / "sign", SIGN_ROOT / "scripts" / "vendor"):
        init_py = d / "__init__.py"
        if d.is_dir() and not init_py.exists():
            init_py.write_text("", encoding="utf-8")

#!/usr/bin/env python3
"""Frozen EXE runtime: extract bundle, set paths."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent
SIGN_ROOT = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))
PURE_SIGN_VENDOR = Path(os.environ.get("PURE_SIGN_VENDOR", ""))
DATA_DIR = Path(os.environ.get("COLLECT_DATA", APP_ROOT / "data"))
_MARKER = ".extracted_v33"

# 内置默认：仅复制 EXE 到服务器即可当中转（MySQL 在本机 127.0.0.1）
_SERVER_DEFAULTS = {
    "COLLECT_BACKEND": "mysql",
    "MYSQL_HOST": "127.0.0.1",
    "MYSQL_PORT": "3306",
    "MYSQL_USER": "fdqc",
    "MYSQL_PASSWORD": "dfyd1234",
    "MYSQL_DATABASE": "dy_live",
    "COLLECT_PORT": "9909",
}


def _exe_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path.cwd()


def _ensure_vendor_init(path: Path) -> None:
    init_py = path / "__init__.py"
    if path.is_dir() and not init_py.exists():
        init_py.write_text("", encoding="utf-8")


def load_env() -> None:
    for key, val in _SERVER_DEFAULTS.items():
        os.environ.setdefault(key, val)
    env_file = _exe_dir() / "server.env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip().lstrip("\ufeff")
        if key:
            os.environ[key] = val.strip()


def _fix_ssl_certificates() -> None:
    if not getattr(sys, "frozen", False):
        return
    try:
        import certifi
        ca = Path(certifi.where())
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            for rel in ("certifi/cacert.pem", "cacert.pem"):
                bundled = Path(meipass) / rel
                if bundled.is_file():
                    ca = bundled
                    break
        os.environ["SSL_CERT_FILE"] = str(ca)
        os.environ["REQUESTS_CA_BUNDLE"] = str(ca)
    except Exception:
        pass


def init() -> None:
    global APP_ROOT, SIGN_ROOT, PURE_SIGN_VENDOR, DATA_DIR
    _fix_ssl_certificates()
    exe_dir = _exe_dir()
    DATA_DIR = exe_dir / "data"
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if getattr(sys, "frozen", False):
        meipass = Path(getattr(sys, "_MEIPASS", exe_dir))
        runtime = exe_dir / "_runtime"
        marker = runtime / _MARKER
        bundle = meipass / "bundle"
        if bundle.is_dir() and not marker.exists():
            if runtime.exists():
                shutil.rmtree(runtime, ignore_errors=True)
            shutil.copytree(bundle, runtime)
            marker.write_text("ok", encoding="utf-8")
        APP_ROOT = runtime / "app"
        SIGN_ROOT = runtime / "sign_root"
        PURE_SIGN_VENDOR = runtime / "sign_vendor"
    else:
        APP_ROOT = Path(__file__).resolve().parent
        SIGN_ROOT = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))
        PURE_SIGN_VENDOR = SIGN_ROOT / "tmp" / "sign-pack-original" / "dy_unified" / "vendor"

    for p in (PURE_SIGN_VENDOR, SIGN_ROOT / "scripts"):
        sp = str(p)
        if p.is_dir() and sp not in sys.path:
            sys.path.append(sp)
    sp = str(APP_ROOT)
    if APP_ROOT.is_dir() and sp not in sys.path:
        sys.path.insert(0, sp)

    _ensure_vendor_init(SIGN_ROOT / "scripts" / "vendor")
    if (PURE_SIGN_VENDOR / "sign").is_dir():
        _ensure_vendor_init(PURE_SIGN_VENDOR / "sign")

    os.environ["COLLECT_APP_ROOT"] = str(APP_ROOT)
    os.environ["DOUYIN_SIGN_ROOT"] = str(SIGN_ROOT)
    os.environ["PURE_SIGN_VENDOR"] = str(PURE_SIGN_VENDOR)
    os.environ["COLLECT_DATA"] = str(DATA_DIR)
#!/usr/bin/env python3
from __future__ import annotations
import shutil
from pathlib import Path

WS = Path(__file__).resolve().parent
SIGN = Path(r"E:\douyin-android-sign")
SIGN_VENDOR = SIGN / "tmp" / "sign-pack-original" / "dy_unified" / "vendor"
OUT = WS / "bundle"

APP_PY = (
    "live_collect_db.py",
    "live_collect_mysql.py",
    "live_collect_store.py",
    "live_collect_server.py",
    "live_collect_web.py",
    "live_collect_client.py",
    "live_boost_client.py",
    "guest_device.py",
    "runtime_paths.py",
    "proxy_utils.py",
    "device_profile_pool.py",
    "device_templates_extra.py",
    "device_register.py",
    "device_warmup.py",
    "live_square.py",
    "device_pool.py",
    "live_audience.py",
    "pure_sign.py",
    "collect_runtime.py",
)

def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    app_dir = OUT / "app"
    app_dir.mkdir(parents=True)
    for name in APP_PY:
        src = WS / name
        if src.is_file():
            shutil.copy2(src, app_dir / name)
    sr = OUT / "sign_root"
    shutil.copytree(SIGN / "config", sr / "config")
    scripts = sr / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(SIGN / "scripts" / "profile_tools.py", scripts / "profile_tools.py")
    shutil.copytree(SIGN / "scripts" / "vendor", scripts / "vendor")
    if SIGN_VENDOR.is_dir():
        shutil.copytree(SIGN_VENDOR, OUT / "sign_vendor")
    else:
        raise SystemExit("sign vendor missing: %s" % SIGN_VENDOR)
    for d in (scripts / "vendor", OUT / "sign_vendor" / "sign"):
        if d.is_dir():
            init_f = d / "__init__.py"
            if not init_f.exists():
                init_f.write_text("", encoding="utf-8")
    print("bundle ready:", OUT)

if __name__ == "__main__":
    main()
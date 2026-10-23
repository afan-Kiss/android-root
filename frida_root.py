"""Ensure douyin-frida-server runs as root (required for spawn/attach)."""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

ADB = Path(r"E:\douyin-android-sign\tools\platform-tools\adb.exe")
SERIAL = "XWEEVKY9QCVKW4R4"


def adb_shell(cmd: str, timeout: int = 30) -> str:
    p = subprocess.run(
        [str(ADB), "-s", SERIAL, "shell", cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return (p.stdout or "").strip()


def ensure_frida_root() -> bool:
    out = adb_shell(
        "su -c 'killall douyin-frida-server 2>/dev/null; "
        "nohup /data/local/tmp/douyin-frida-server >/dev/null 2>&1 & "
        "sleep 1; ps -A | grep frida'"
    )
    ok = "root" in out and "douyin-frida" in out
    if not ok:
        print("[frida] WARN ensure_frida_root:", out[:200] or "(empty)")
    time.sleep(1)
    return ok
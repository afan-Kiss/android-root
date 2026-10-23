#!/usr/bin/env python3
"""ADB helpers: wake screen, ensure frida + Douyin process (no UI taps)."""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

ADB = Path(r"E:\douyin-android-sign\tools\platform-tools\adb.exe")
SERIAL = "XWEEVKY9QCVKW4R4"
PKG = "com.ss.android.ugc.aweme"


def adb(*args: str, timeout: int = 60) -> str:
    p = subprocess.run(
        [str(ADB), "-s", SERIAL, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return (p.stdout or "").strip()


def wake_screen() -> None:
    adb("shell", "input", "keyevent", "224")


def ensure_frida_server() -> bool:
    from frida_root import ensure_frida_root

    return ensure_frida_root()


def pidof_douyin() -> int:
    out = adb("shell", "pidof", PKG)
    if not out:
        return 0
    try:
        return int(out.split()[0])
    except (ValueError, IndexError):
        return 0


def launch_douyin(wait_sec: float = 18.0) -> int:
    wake_screen()
    pid = pidof_douyin()
    if pid > 0:
        return pid
    adb("shell", "monkey", "-p", PKG, "-c", "android.intent.category.LAUNCHER", "1")
    deadline = time.time() + max(wait_sec, 8.0)
    while time.time() < deadline:
        pid = pidof_douyin()
        if pid > 0:
            return pid
        time.sleep(2.0)
    return 0


def ensure_douyin_running(wait_sec: float = 20.0) -> int:
    wake_screen()
    ensure_frida_server()
    pid = launch_douyin(wait_sec=wait_sec)
    if pid <= 0:
        adb("shell", "su", "-c", f"am force-stop {PKG}")
        time.sleep(2)
        pid = launch_douyin(wait_sec=wait_sec)
    return pid

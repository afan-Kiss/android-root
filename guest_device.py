#!/usr/bin/env python3
"""Anonymous guest device: register -> warmup -> optional trust -> enter/ping."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from device_register import register_with_retry
from device_warmup import full_warmup, merge_reg_profile
from live_audience import enter_room, ping_room
from profile_tools import load_json

ROOT = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))


def ids_from_reg(reg: dict) -> dict[str, str]:
    return {
        "device_id": str(reg["device_id"]),
        "install_id": str(reg["install_id"]),
        "openudid": str(reg.get("openudid") or ""),
        "cdid": str(reg.get("cdid") or ""),
        "device_token": str(reg.get("device_token") or ""),
    }


def apply_trust_profile(dev: dict, trust: dict) -> dict:
    prof_path = Path(str(trust.get("profile") or ""))
    if prof_path.is_file():
        reg_prof = load_json(prof_path)
        if reg_prof.get("mssdkPrefs"):
            dev = dict(dev)
            dev["mssdkPrefs"] = reg_prof["mssdkPrefs"]
    return dev


def register_guest(
    profile: dict,
    *,
    proxies: dict | None = None,
    reg_retries: int = 4,
    reg_delay: float = 6.0,
    warmup: bool = True,
    app_log_rounds: int = 2,
    trust: bool = False,
    phone_sdi: bool = False,
) -> dict[str, Any]:
    """Register a fresh anonymous device; optionally warmup + MSSDK trust."""
    reg = register_with_retry(profile, retries=reg_retries, delay=reg_delay, timeout=30, proxies=proxies)
    out: dict[str, Any] = {"reg": reg, "warmup": None, "trust": None, "dev": merge_reg_profile(profile, reg)}
    if warmup:
        out["warmup"] = full_warmup(profile, reg, proxies=proxies, app_log_rounds=app_log_rounds, pause=0.8)
    if trust:
        from mssdk_trust import trust_pipeline

        tp = trust_pipeline(profile, reg, proxies=proxies, phone_sdi=phone_sdi, phone_oracle=phone_sdi)
        out["trust"] = tp
        out["dev"] = apply_trust_profile(out["dev"], tp)
    return out


def enter_as_guest(
    profile: dict,
    room_id: str,
    ids: dict,
    *,
    proxies: dict | None = None,
) -> dict:
    return enter_room(profile, room_id, ids, proxies=proxies)


def watch_as_guest(
    profile: dict,
    room_id: str,
    ids: dict,
    *,
    duration: int = 60,
    ping_interval: int = 12,
    proxies: dict | None = None,
) -> dict:
    enter = enter_room(profile, room_id, ids, proxies=proxies)
    if not enter.get("ok"):
        return {"ok": False, "stage": "enter", "enter": enter, "pings": 0}
    end = time.time() + max(duration, 10)
    pings = 0
    wait = ping_interval or 12
    while time.time() < end:
        ping = ping_room(profile, room_id, ids, proxies=proxies)
        pings += 1
        if ping.get("ok"):
            wait = max(10, min(int(ping.get("next_ping") or wait), 300))
        time.sleep(min(wait, max(3, int(end - time.time()))))
    return {"ok": True, "stage": "done", "enter": enter, "pings": pings}


def guest_from_pool_row(profile: dict, row: dict) -> tuple[dict, dict]:
    dev = merge_reg_profile(profile, row)
    return dev, ids_from_reg(row)

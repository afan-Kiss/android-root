#!/usr/bin/env python3
"""Unified pipeline: demo | phone | protocol | auto."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"E:\douyin-android-sign")
WS = Path(r"e:\我的源码目录\安卓ROOT")
for p in (WS, ROOT / "capture", ROOT / "scripts"):
    if str(p) not in sys.path:
        sys.path.append(str(p))

from device_pool import add_device, load_pool, save_pool
from device_register import register_once
from device_warmup import merge_reg_profile
from live_audience import enter_room, ping_room, resolve_room_id
from mssdk_trust import apply_sdi_hex, is_trusted_sdi_token, trust_pipeline
from profile_tools import load_json
from proxy_utils import fetch_proxy

ROOM_DEFAULT = "7699144929192184627"
PROFILE = ROOT / "config/device_profile.json"
SDI_TXT = ROOT / "config/captured_sdi_token.txt"


def profile_ids(profile: dict) -> dict:
    return {
        "device_id": str(profile.get("deviceId") or ""),
        "install_id": str(profile.get("installId") or ""),
        "openudid": str(profile.get("openudid") or ""),
        "cdid": str(profile.get("cdid") or ""),
        "device_token": "",
    }


def sdi_from_profile(profile: dict) -> str:
    prefs = profile.get("mssdkPrefs") or {}
    for k in ("1128-1128-sdi", "1128-0-sdi", "sdi_token"):
        v = prefs.get(k)
        if is_trusted_sdi_token(str(v or "")):
            return str(v)
    if SDI_TXT.is_file():
        v = SDI_TXT.read_text(encoding="utf-8").strip()
        if is_trusted_sdi_token(v):
            return v
    return ""


def watch(profile: dict, room: str, ids: dict, watch_sec: int, ping_iv: int, proxies=None) -> dict:
    enter = enter_room(profile, room, ids, proxies=proxies)
    print("[enter] ok=", enter.get("ok"), "reason=", enter.get("reason"))
    if not enter.get("ok"):
        return {"ok": False, "enter": enter, "pings": 0}
    end = time.time() + max(watch_sec, 10)
    pings = 0
    wait = ping_iv
    while time.time() < end:
        p = ping_room(profile, room, ids, proxies=proxies)
        pings += 1
        print(f"[ping] #{pings} ok={p.get('ok')}")
        if p.get("ok"):
            wait = max(10, min(int(p.get("next_ping") or wait), 120))
        time.sleep(min(wait, max(3, int(end - time.time()))))
    return {"ok": True, "enter": enter, "pings": pings}


def run_demo(profile: dict, room: str, watch_sec: int, ping_iv: int) -> int:
    ids = profile_ids(profile)
    res = watch(profile, room, ids, watch_sec, ping_iv)
    if res.get("ok"):
        pool = load_pool()
        save_pool(add_device(pool, {**ids, "source": "demo", "verified_enter": True}, verified=True))
    return 0 if res.get("ok") else 2


def run_phone(profile: dict, room: str, watch_sec: int, ping_iv: int) -> int:
    script = ROOT / "scripts/spawn-capture-sdi.py"
    r = subprocess.run([sys.executable, str(script)], cwd=str(ROOT))
    if r.returncode != 0:
        print("[phone] SDI capture failed")
        return r.returncode
    profile = load_json(PROFILE)
    token = SDI_TXT.read_text(encoding="utf-8").strip() if SDI_TXT.is_file() else ""
    if not is_trusted_sdi_token(token):
        print("[phone] no trusted SDI hex after capture")
        return 2
    print(f"[phone] sdi len={len(token)}")
    return run_demo(profile, room, watch_sec, ping_iv)


def run_protocol(
    profile: dict,
    room: str,
    watch_sec: int,
    ping_iv: int,
    phone_fallback: bool,
    phone_sdi: bool = False,
) -> int:
    reg = None
    px = None
    for i in range(12):
        px = fetch_proxy()
        try:
            reg = register_once(profile, proxies=px, timeout=25)
            if str(reg.get("device_id", "0")) == "0":
                raise RuntimeError("device_id=0")
            print(f"[reg] ok did={reg['device_id']}")
            break
        except Exception as e:
            print(f"[reg] {i+1} fail: {e}")
            time.sleep(3)
    if not reg:
        return 1
    if phone_fallback:
        os.environ["PHONE_SDI_TRUST"] = "1"
    trust = trust_pipeline(profile, reg, proxies=px, phone_sdi=phone_sdi, phone_oracle=phone_sdi)
    print("[trust]", json.dumps(
        {k: trust.get(k) for k in ("trust_ok", "blocker", "sdi_source", "sdi_applied")},
        ensure_ascii=False,
    ))
    dev = merge_reg_profile(profile, reg)
    prof_path = Path(trust.get("profile") or "")
    if prof_path.is_file():
        reg_prof = load_json(prof_path)
        if reg_prof.get("mssdkPrefs"):
            dev["mssdkPrefs"] = reg_prof["mssdkPrefs"]
    ids = {
        "device_id": reg["device_id"],
        "install_id": reg["install_id"],
        "openudid": reg["openudid"],
        "cdid": reg.get("cdid", ""),
        "device_token": reg.get("device_token") or "",
    }
    res = watch(dev, room, ids, watch_sec, ping_iv, proxies=px)
    out = ROOT / "tmp" / "pipeline_result.json"
    out.write_text(json.dumps({"reg": reg, "trust": trust, "result": res}, ensure_ascii=False, indent=2), encoding="utf-8")
    if res.get("ok"):
        pool = load_pool()
        src = "protocol-phone" if phone_sdi else "protocol"
        save_pool(add_device(pool, {**ids, "source": src, "verified_enter": True}, verified=True))
    return 0 if res.get("ok") else 2


def run_auto(profile: dict, room: str, watch_sec: int, ping_iv: int) -> int:
    if sdi_from_profile(profile) and profile_ids(profile)["device_id"]:
        print("[auto] profile has hex SDI -> demo")
        return run_demo(profile, room, watch_sec, ping_iv)
    print("[auto] no SDI -> phone capture")
    rc = run_phone(profile, room, watch_sec, ping_iv)
    if rc == 0:
        return 0
    print("[auto] phone failed -> try protocol (no SDI fallback)")
    return run_protocol(profile, room, min(watch_sec, 15), ping_iv, phone_fallback=False)


def run_refresh(profile: dict, room: str, watch_sec: int, ping_iv: int) -> int:
    """Phone cold spawn SDI capture, then enter+ping (safe: only force-stop/spawn Douyin)."""
    script = ROOT / "scripts/spawn-capture-sdi.py"
    print("[refresh] spawn-capture-sdi (phone open/close only)")
    r = subprocess.run([sys.executable, str(script)], cwd=str(ROOT))
    if r.returncode != 0:
        return r.returncode
    profile = load_json(PROFILE)
    return run_demo(profile, room, watch_sec, ping_iv)


def run_boost(profile: dict, room: str, watch_sec: int, ping_iv: int) -> int:
    """Refresh phone SDI + enter profile device + all verified pool devices."""
    rc = run_refresh(profile, room, watch_sec, ping_iv)
    if rc != 0:
        return rc
    pool = load_pool()
    verified = [r for r in pool if r.get("verified_enter") and r.get("device_id")]
    if len(verified) < 2:
        print("[boost] pool has <2 verified devices, refresh-only done")
        return 0
    boost = WS / "live_boost.py"
    print(f"[boost] pool enter n={min(len(verified), 4)}")
    r = subprocess.run(
        [
            sys.executable,
            str(boost),
            "--room",
            room,
            "--use-pool",
            "--count",
            str(min(len(verified), 4)),
            "--watch",
            str(watch_sec),
            "--ping-interval",
            str(ping_iv),
        ],
        cwd=str(WS),
    )
    return 0 if r.returncode == 0 else r.returncode


def main() -> int:
    ap = argparse.ArgumentParser(description="Douyin android audience pipeline")
    ap.add_argument(
        "--mode",
        choices=("auto", "demo", "phone", "protocol", "protocol-phone", "refresh", "boost"),
        default="auto",
    )
    ap.add_argument("--room", default=ROOM_DEFAULT)
    ap.add_argument("--watch", type=int, default=45)
    ap.add_argument("--ping-interval", type=int, default=12)
    ap.add_argument("--phone-sdi-fallback", action="store_true", help="protocol: apply captured SDI (same device only)")
    args = ap.parse_args()
    profile = load_json(PROFILE)
    room = resolve_room_id(args.room)
    if args.mode == "demo":
        return run_demo(profile, room, args.watch, args.ping_interval)
    if args.mode == "phone":
        return run_phone(profile, room, args.watch, args.ping_interval)
    if args.mode == "protocol":
        return run_protocol(profile, room, args.watch, args.ping_interval, args.phone_sdi_fallback)
    if args.mode == "protocol-phone":
        return run_protocol(profile, room, args.watch, args.ping_interval, False, phone_sdi=True)
    if args.mode == "refresh":
        return run_refresh(profile, room, args.watch, args.ping_interval)
    if args.mode == "boost":
        return run_boost(profile, room, args.watch, args.ping_interval)
    return run_auto(profile, room, args.watch, args.ping_interval)


if __name__ == "__main__":
    raise SystemExit(main())
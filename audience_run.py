#!/usr/bin/env python3
"""E2E audience: profile demo | protocol register+trust+enter+ping."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(r"E:\douyin-android-sign")
sys.path.insert(0, str(ROOT / "scripts"))

from device_register import register_once
from device_warmup import merge_reg_profile
from live_audience import enter_room, ping_room, resolve_room_id
from mssdk_trust import trust_pipeline
from profile_tools import load_json
from proxy_utils import fetch_proxy


def profile_ids(profile: dict) -> dict:
    return {
        "device_id": str(profile.get("deviceId") or ""),
        "install_id": str(profile.get("installId") or ""),
        "openudid": str(profile.get("openudid") or ""),
        "cdid": str(profile.get("cdid") or ""),
        "device_token": "",
    }


def run_profile_demo(profile: dict, room: str, watch: int, ping_iv: int) -> int:
    ids = profile_ids(profile)
    enter = enter_room(profile, room, ids)
    print("[demo] enter ok=", enter.get("ok"), "reason=", enter.get("reason"))
    if not enter.get("ok"):
        return 2
    end = time.time() + max(watch, 10)
    pings = 0
    wait = ping_iv
    while time.time() < end:
        p = ping_room(profile, room, ids)
        pings += 1
        print(f"[demo] ping#{pings} ok={p.get('ok')} next={p.get('next_ping')}")
        if p.get("ok"):
            wait = max(10, min(int(p.get("next_ping") or wait), 120))
        time.sleep(min(wait, max(3, int(end - time.time()))))
    print(f"[demo] done pings={pings}")
    return 0


def run_protocol(profile: dict, room: str, watch: int, ping_iv: int) -> int:
    reg = None
    px = None
    for i in range(15):
        px = fetch_proxy()
        try:
            reg = register_once(profile, proxies=px, timeout=25)
            if str(reg.get("device_id", "0")) == "0":
                raise RuntimeError("device_id=0 rate limited")
            print(f"[reg] ok did={reg['device_id']}")
            break
        except Exception as e:
            print(f"[reg] {i+1} fail: {e}")
            time.sleep(3)
    if not reg:
        return 1
    trust = trust_pipeline(profile, reg, proxies=px)
    print("[trust]", json.dumps(
        {k: trust[k] for k in ("trust_ok", "blocker", "sdi_source", "sdi_applied") if k in trust},
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
        "cdid": reg["cdid"],
        "device_token": reg.get("device_token") or "",
    }
    enter = enter_room(dev, room, ids, proxies=px)
    print("[enter] ok=", enter.get("ok"), "reason=", enter.get("reason"))
    out = ROOT / "tmp" / "audience_run_result.json"
    out.write_text(
        json.dumps({"reg": reg, "trust": trust, "enter": enter}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if not enter.get("ok"):
        return 2
    end = time.time() + max(watch, 10)
    pings = 0
    wait = ping_iv
    while time.time() < end:
        p = ping_room(dev, room, ids, proxies=px)
        pings += 1
        print(f"[ping] #{pings} ok={p.get('ok')}")
        if p.get("ok"):
            wait = max(10, min(int(p.get("next_ping") or wait), 120))
        time.sleep(min(wait, max(3, int(end - time.time()))))
    print(f"[done] pings={pings}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--room", default="7699144929192184627")
    ap.add_argument("--mode", choices=("demo", "protocol", "refresh"), default="demo")
    ap.add_argument("--watch", type=int, default=45)
    ap.add_argument("--ping-interval", type=int, default=12)
    args = ap.parse_args()
    profile = load_json(ROOT / "config/device_profile.json")
    room = resolve_room_id(args.room)
    if args.mode == "demo":
        return run_profile_demo(profile, room, args.watch, args.ping_interval)
    if args.mode == "refresh":
        import subprocess
        script = Path(r"e:\我的源码目录\安卓ROOT\pipeline_run.py")
        return subprocess.call(
            [sys.executable, str(script), "--mode", "refresh", "--room", room,
             "--watch", str(args.watch), "--ping-interval", str(args.ping_interval)],
        )
    return run_protocol(profile, room, args.watch, args.ping_interval)


if __name__ == "__main__":
    raise SystemExit(main())
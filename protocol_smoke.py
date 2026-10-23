#!/usr/bin/env python3
"""Single-device protocol smoke: register -> full_warmup -> enter -> ping."""
from __future__ import annotations
import argparse, json, sys, time
from pathlib import Path
ROOT = Path(r"E:\douyin-android-sign")
sys.path.insert(0, str(ROOT / "scripts"))
from profile_tools import load_json
from device_register import register_with_retry
from device_warmup import full_warmup, merge_reg_profile
from live_audience import enter_room, ping_room, resolve_room_id
from proxy_utils import fetch_proxy

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--room", default="7699144929192184627")
    ap.add_argument("--profile", default=str(ROOT / "config/device_profile.json"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    profile = load_json(args.profile)
    room_id = resolve_room_id(args.room)
    px = fetch_proxy()
    reg = register_with_retry(profile, retries=5, delay=10.0, proxies=px, timeout=25)
    warm = full_warmup(profile, reg, proxies=px, app_log_rounds=3)
    dev = merge_reg_profile(profile, reg)
    ids = dict(device_id=reg["device_id"], install_id=reg["install_id"], openudid=reg["openudid"],
               cdid=reg["cdid"], device_token=reg.get("device_token") or "")
    enter = enter_room(dev, room_id, ids, proxies=px)
    ping = ping_room(dev, room_id, ids, proxies=px) if enter.get("ok") else {"ok": False}
    out = {"device_id": reg["device_id"], "install_id": reg["install_id"], "warmup": warm,
           "enter": enter, "ping": ping}
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print("did", reg["device_id"], "enter", enter.get("ok"), "reason", enter.get("reason"))
    return 0 if enter.get("ok") else 2

if __name__ == "__main__":
    raise SystemExit(main())
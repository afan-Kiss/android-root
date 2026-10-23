#!/usr/bin/env python3
"""Register -> MSSDK trust (MetaSec get_token) -> full-sign enter."""
from __future__ import annotations
import json, sys, time
from pathlib import Path
ROOT = Path(r"E:\douyin-android-sign")
sys.path.insert(0, str(ROOT / "scripts"))
from profile_tools import load_json
from device_register import register_once
from device_warmup import merge_reg_profile
from live_audience import enter_room
from mssdk_trust import trust_pipeline
from proxy_utils import fetch_proxy

ROOM = "7699144929192184627"

def main():
    profile = load_json(ROOT / "config/device_profile.json")
    reg = None
    px = None
    for i in range(20):
        px = fetch_proxy()
        try:
            reg = register_once(profile, proxies=px, timeout=25)
            print(f"[reg] ok did={reg['device_id']} token={bool(reg.get('device_token'))}")
            break
        except Exception as e:
            print(f"[reg] {i+1} fail: {e}")
            time.sleep(3)
    if not reg:
        return 1
    trust = trust_pipeline(profile, reg, proxies=px)
    print("[trust]", json.dumps({k: trust[k] for k in trust if k != "warmup"}, ensure_ascii=False))
    dev = merge_reg_profile(profile, reg)
    prof_path = Path(trust.get("profile") or "")
    if prof_path.is_file():
        reg_prof = load_json(prof_path)
        if reg_prof.get("mssdkPrefs"):
            dev["mssdkPrefs"] = reg_prof["mssdkPrefs"]
    ids = dict(device_id=reg["device_id"], install_id=reg["install_id"], openudid=reg["openudid"],
               cdid=reg["cdid"], device_token=reg.get("device_token") or "")
    enter = enter_room(dev, ROOM, ids, proxies=px)
    print("[enter] ok=", enter.get("ok"), "reason=", enter.get("reason"))
    out = ROOT / "tmp" / "trust_test_result.json"
    out.write_text(json.dumps({"reg": {"device_id": reg["device_id"]}, "trust": trust, "enter": enter},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if enter.get("ok") else 2

if __name__ == "__main__":
    raise SystemExit(main())
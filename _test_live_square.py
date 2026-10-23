#!/usr/bin/env python3
"""Probe live square / feed APIs: web vs Android signed."""
from __future__ import annotations
import json, sys, time
from pathlib import Path
import requests
ROOT_SIGN = Path(r"E:\douyin-android-sign")
WS = Path(__file__).resolve().parent
sys.path.insert(0, str(WS))
sys.path.insert(0, str(ROOT_SIGN / "scripts"))
from live_audience import signed_request
from profile_tools import load_json
from device_register import register_with_retry
from device_warmup import merge_reg_profile, full_warmup
from proxy_utils import fetch_proxy
PROFILE = ROOT_SIGN / "config/device_profile.json"
FEED_PATHS = ["/webcast/feed/", "/webcast/room/feed/", "/webcast/distribution/", "/webcast/openapi/feed/", "/aweme/v1/live/feed/", "/aweme/v2/live/feed/"]
HOSTS = ("https://webcast5-normal-lf.amemv.com", "https://webcast3-normal-c-hl.amemv.com", "https://webcast.amemv.com", "https://api5-normal.amemv.com")

def test_web_feed():
    r = requests.get("https://live.douyin.com/webcast/feed/", params={"aid":"6383","device_platform":"web","count":"8"}, headers={"User-Agent":"Mozilla/5.0"}, timeout=20)
    out = {"status": r.status_code, "rooms": []}
    j = r.json()
    for item in (j.get("data") or [])[:5]:
        d = item.get("data") or item
        out["rooms"].append({"room_id": str(d.get("id_str") or d.get("id") or ""), "status": d.get("status"), "title": (d.get("title") or "")[:40], "nickname": ((d.get("owner") or {}).get("nickname") or "")[:20], "user_count": d.get("user_count")})
    out["total"] = len(j.get("data") or [])
    return out

def feed_params(profile, ids):
    b, d = profile.get("build") or {}, profile.get("display") or {}
    return {"webcast_sdk_version":"3880","webcast_version_code":"3880","manifest_version_code":str(profile.get("manifestVersionCode","400701")),"app_type":"normal","iid":str(ids.get("install_id") or ""),"channel":str(profile.get("channel","googleplay")),"device_type":str(b.get("model","PGZ110")),"language":"zh","resolution":str(d.get("resolution","1080*2246")).replace("x","*"),"openudid":str(ids.get("openudid") or ""),"update_version_code":str(profile.get("updateVersionCode","40709900")),"os_api":str(b.get("sdk_int","35")),"dpi":str(d.get("dpi","480")),"ac":"wifi","device_id":str(ids.get("device_id") or ""),"mcc_mnc":"46000","os_version":str(b.get("release","15")),"version_code":str(profile.get("versionCode","400701")),"app_name":"aweme","version_name":str(profile.get("appVersion","40.7.0")),"device_brand":str(b.get("brand","OnePlus")),"ssmix":"a","device_platform":"android","aid":str(profile.get("appId","1128")),"cdid":str(ids.get("cdid") or ""),"count":"20","max_time":"0","enter_source":"live_square","live_reason":"live_square","req_from":"live_square","_rticket":str(int(time.time()*1000))}

def probe_signed_feed(profile, ids, proxies):
    params = feed_params(profile, ids)
    results = []
    for host in HOSTS:
        for path in FEED_PATHS:
            try:
                r = signed_request(host, path, params, profile, "GET", proxies=proxies)
                text = (r.text or "").strip()
                entry = {"host": host, "path": path, "http": r.status_code, "len": len(text), "preview": text[:180]}
                if r.status_code == 200 and text:
                    try:
                        body = r.json()
                        entry["status_code"] = body.get("status_code")
                        data = body.get("data") or []
                        if isinstance(data, list):
                            entry["items"] = len(data)
                            if data and isinstance(data[0], dict):
                                d0 = data[0].get("data") or data[0]
                                if isinstance(d0, dict):
                                    entry["sample_room"] = str(d0.get("id_str") or d0.get("id") or "")
                    except Exception:
                        pass
                results.append(entry)
            except Exception as e:
                results.append({"host": host, "path": path, "error": str(e)})
    return results

def main():
    print("=== WEB FEED ===")
    print(json.dumps(test_web_feed(), ensure_ascii=False, indent=2))
    print("=== REGISTER + SIGNED ===")
    profile = load_json(str(PROFILE))
    px = fetch_proxy()
    reg = register_with_retry(profile, retries=3, delay=8.0, proxies=px, timeout=25)
    print("did", reg.get("device_id"))
    warm = full_warmup(profile, reg, proxies=px, app_log_rounds=2)
    print("warmup", warm.get("ok"))
    dev = merge_reg_profile(profile, reg)
    ids = {"device_id": reg["device_id"], "install_id": reg["install_id"], "openudid": reg.get("openudid",""), "cdid": reg.get("cdid","")}
    signed = probe_signed_feed(dev, ids, px)
    hits = [x for x in signed if x.get("http")==200 and x.get("len",0)>50]
    print("hits", len(hits), "/", len(signed))
    for x in hits[:12]:
        print(json.dumps(x, ensure_ascii=False))

if __name__ == "__main__":
    main()

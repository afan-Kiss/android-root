#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, sys, time
from pathlib import Path
ROOT_SIGN = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))
APP_ROOT = Path(os.environ.get("COLLECT_APP_ROOT", Path(__file__).resolve().parent))
for p in (APP_ROOT, ROOT_SIGN / "scripts"):
    sp = str(p)
    if p.is_dir() and sp not in sys.path:
        sys.path.insert(0, sp)
from device_warmup import merge_reg_profile
from live_audience import WEBCAST_SDK, signed_request
from profile_tools import load_json
FEED_PATH = "/webcast/feed/"
FEED_HOSTS = ("https://webcast5-normal-lf.amemv.com", "https://webcast3-normal-c-hl.amemv.com", "https://webcast.amemv.com")
DEFAULT_PROFILE = ROOT_SIGN / "config/device_profile.json"

def feed_params(profile, ids, max_time="0", count=20):
    b, d = profile.get("build") or {}, profile.get("display") or {}
    return {"webcast_sdk_version": WEBCAST_SDK, "webcast_version_code": WEBCAST_SDK, "manifest_version_code": str(profile.get("manifestVersionCode", "400701")), "app_type": "normal", "iid": str(ids.get("install_id") or profile.get("installId") or ""), "channel": str(profile.get("channel", "googleplay")), "device_type": str(b.get("model", "PGZ110")), "language": "zh", "resolution": str(d.get("resolution", "1080*2246")).replace("x", "*"), "openudid": str(ids.get("openudid") or profile.get("openudid", "")), "update_version_code": str(profile.get("updateVersionCode", "40709900")), "os_api": str(b.get("sdk_int", "35")), "dpi": str(d.get("dpi", "480")), "ac": "wifi", "device_id": str(ids.get("device_id") or profile.get("deviceId") or ""), "mcc_mnc": "46000", "os_version": str(b.get("release", "15")), "version_code": str(profile.get("versionCode", "400701")), "app_name": "aweme", "version_name": str(profile.get("appVersion", "40.7.0")), "device_brand": str(b.get("brand", "OnePlus")), "ssmix": "a", "device_platform": "android", "aid": str(profile.get("appId", "1128")), "cdid": str(ids.get("cdid") or profile.get("cdid", "")), "count": str(count), "max_time": str(max_time), "is_draw": "0", "enter_source": "live_square", "live_reason": "live_square", "req_from": "live_square", "content_type": "0", "is_login": "0", "_rticket": str(int(time.time() * 1000))}

def parse_room(item):
    d = item.get("data") if isinstance(item.get("data"), dict) else item
    if not isinstance(d, dict): return None
    rid = str(d.get("id_str") or d.get("id") or "").strip()
    if not rid: return None
    owner = d.get("owner") or {}
    return {"room_id": rid, "title": d.get("title") or "", "status": d.get("status"), "user_count": d.get("user_count"), "nickname": owner.get("nickname") or "", "uid": str(owner.get("id_str") or owner.get("id") or ""), "sec_uid": owner.get("sec_uid") or "", "web_rid": d.get("web_rid")}

def fetch_feed_page(profile, ids, max_time, count, host_idx, proxies=None):
    params = feed_params(profile, ids, max_time=max_time, count=count)
    last_err = ""
    for attempt in range(len(FEED_HOSTS)):
        host = FEED_HOSTS[(host_idx + attempt) % len(FEED_HOSTS)]
        try:
            try:
                from live_audience import _trace
                _trace("feed try %s" % host)
            except Exception:
                pass
            r = signed_request(host, FEED_PATH, params, profile, "GET", proxies=proxies)
            raw = r.content or b""
            if len(raw) >= 2 and raw[:2] == b"\x1f\x8b":
                try:
                    import gzip
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            text = raw.decode("utf-8", errors="replace").strip()
            try:
                from live_audience import _trace
                _trace("feed rsp %s http=%s len=%s" % (host, r.status_code, len(text)))
            except Exception:
                pass
            if r.status_code == 200 and len(text) > 100:
                try:
                    body = json.loads(text)
                except json.JSONDecodeError as e:
                    last_err = "json_err %s" % e
                    continue
                try:
                    from live_audience import _trace
                    _trace("feed json sc=%s items=%s" % (body.get("status_code"), len(body.get("data") or [])))
                except Exception:
                    pass
                if body.get("status_code") == 0:
                    return body, (host_idx + attempt) % len(FEED_HOSTS)
                last_err = "status_code=%s msg=%s" % (body.get("status_code"), str(body.get("data"))[:80])
            else:
                last_err = "http=%s len=%s head=%s" % (r.status_code, len(text), text[:80])
        except Exception as e:
            last_err = str(e)[:120]
        time.sleep(0.3)
    if last_err:
        print("[feed] fail %s" % last_err, flush=True)
        try:
            from live_audience import _trace
            _trace("[feed] fail %s" % last_err)
        except Exception:
            pass
    return None, host_idx

def load_devices(profile, pool_path):
    from device_pool import load_pool, profile_entry
    rows = [r for r in load_pool(pool_path) if r.get("device_id") and r.get("install_id")]
    return rows or [profile_entry(profile)]

def collect_rooms(target, profile, devices, count=20, pause=0.12, max_pages=600):
    seen, rooms = set(), []
    stats = {"target": target, "pages": 0, "empty_pages": 0, "raw_items": 0, "dup_skipped": 0, "devices_used": len(devices), "errors": 0}
    t0 = time.time(); max_time = "0"; has_more = True; host_idx = 0; dev_idx = 0
    while len(rooms) < target and has_more and stats["pages"] < max_pages:
        row = devices[dev_idx % len(devices)]
        dev = merge_reg_profile(profile, row)
        ids = {"device_id": row["device_id"], "install_id": row["install_id"], "openudid": row.get("openudid", ""), "cdid": row.get("cdid", "")}
        body, host_idx = fetch_feed_page(dev, ids, max_time, count, host_idx)
        stats["pages"] += 1
        if not body:
            stats["empty_pages"] += 1; stats["errors"] += 1; dev_idx += 1; time.sleep(0.8); continue
        extra = body.get("extra") or {}
        has_more = bool(extra.get("has_more")); max_time = str(extra.get("max_time") or max_time)
        items = body.get("data") or []; stats["raw_items"] += len(items); new_on_page = 0
        for item in items:
            room = parse_room(item)
            if not room: continue
            rid = room["room_id"]
            if rid in seen: stats["dup_skipped"] += 1; continue
            seen.add(rid); room["page"] = stats["pages"]; rooms.append(room); new_on_page += 1
            if len(rooms) >= target: break
        if new_on_page == 0 and has_more: dev_idx += 1
        if stats["pages"] % 20 == 0:
            print("[collect] page=%s unique=%s/%s dup=%s elapsed=%.1fs" % (stats["pages"], len(rooms), target, stats["dup_skipped"], time.time()-t0), flush=True)
        time.sleep(pause)
    elapsed = time.time() - t0
    stats["collected"] = len(rooms); stats["elapsed_sec"] = round(elapsed, 2)
    stats["pages_per_sec"] = round(stats["pages"] / elapsed, 3) if elapsed else 0
    stats["rooms_per_sec"] = round(len(rooms) / elapsed, 3) if elapsed else 0
    stats["rooms_per_page"] = round(len(rooms) / stats["pages"], 2) if stats["pages"] else 0
    stats["has_more"] = has_more
    return {"stats": stats, "rooms": rooms}

def main():
    from device_pool import DEFAULT_POOL
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=500)
    ap.add_argument("--profile", default=str(DEFAULT_PROFILE))
    ap.add_argument("--pool", default=str(DEFAULT_POOL))
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--pause", type=float, default=0.12)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    profile = load_json(args.profile)
    devices = load_devices(profile, Path(args.pool))
    print("[start] target=%s devices=%s count=%s" % (args.target, len(devices), args.count))
    result = collect_rooms(args.target, profile, devices, count=args.count, pause=args.pause)
    stats = result["stats"]
    out_path = Path(args.out) if args.out else ROOT_SIGN / "tmp" / ("live_square_%s.json" % stats["collected"])
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("[done] collected=%s/%s pages=%s raw=%s dup_skipped=%s empty=%s elapsed=%ss speed=%s rooms/s pages_per_sec=%s avg_new_per_page=%s" % (stats["collected"], args.target, stats["pages"], stats["raw_items"], stats["dup_skipped"], stats["empty_pages"], stats["elapsed_sec"], stats["rooms_per_sec"], stats["pages_per_sec"], stats["rooms_per_page"]))
    print("[out] %s" % out_path)
    for i, r in enumerate(result["rooms"][:10], 1):
        print("  %s. %s | %s | %s | %s" % (i, r["room_id"], r["user_count"], r["nickname"], (r["title"] or "")[:40]))
    if len(result["rooms"]) > 10:
        print("  ... +%s more in file" % (len(result["rooms"]) - 10))
    return 0 if stats["collected"] >= args.target else 1

if __name__ == "__main__":
    raise SystemExit(main())
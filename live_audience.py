#!/usr/bin/env python3
"""Android live anonymous audience: enter + ping (device_id/iid, no cookie)."""
from __future__ import annotations
import argparse, gzip, json, os, re, sys, time, urllib.parse, urllib.request
from pathlib import Path
import requests


def _trace(msg: str) -> None:
    try:
        import collect_runtime
        p = collect_runtime._exe_dir() / "feed_trace.log"
        with open(p, "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
    except Exception:
        pass


def _urllib_get(url: str, headers: dict, timeout: int = 25) -> requests.Response:
    hdrs = dict(headers)
    hdrs.pop("Accept-Encoding", None)
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        status = resp.status
        resp_hdrs = dict(resp.headers)
    enc = (resp_hdrs.get("Content-Encoding") or "").lower()
    if enc == "gzip" or (len(body) >= 2 and body[:2] == b"\x1f\x8b"):
        try:
            body = gzip.decompress(body)
        except Exception:
            pass
    r = requests.Response()
    r.status_code = status
    r._content = body
    r.headers = resp_hdrs
    r.encoding = "utf-8"
    r.url = url
    return r

ROOT = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))
_sp = str(ROOT / "scripts")
if _sp not in sys.path:
    sys.path.insert(0, _sp)
from profile_tools import load_json

SIGN_URL = "http://127.0.0.1:5099"
USE_PURE_SIGN = True
WEBCAST_HOSTS = (
    "https://webcast5-normal-lf.amemv.com",
    "https://webcast3-normal-c-hl.amemv.com",
    "https://webcast.amemv.com",
)
WEBCAST_SDK = "3880"
PING_PATH = "/webcast/room/ping/audience/"


def sign(url: str, body: str = "", did: str = "", iid: str = "") -> dict[str, str]:
    if USE_PURE_SIGN:
        from pure_sign import sign_url
        return sign_url(url, body=body, device_id=did)
    payload = json.dumps({"url": url, "data": body, "cookie": "", "device_id": did, "install_id": iid}).encode()
    req = urllib.request.Request(
        SIGN_URL + "/sign", data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = json.loads(resp.read().decode())
    if not data.get("ok"):
        raise RuntimeError(data.get("error") or "sign failed")
    return {str(k).lower(): str(v) for k, v in (data.get("result") or {}).items() if v}


def base_params(profile: dict, room_id: str, ids: dict | None = None) -> dict[str, str]:
    ids = ids or {}
    b, d = profile.get("build") or {}, profile.get("display") or {}
    did = str(ids.get("device_id") or profile.get("deviceId") or profile.get("device_id") or "")
    iid = str(ids.get("install_id") or profile.get("installId") or profile.get("install_id") or "")
    return {
        "webcast_sdk_version": WEBCAST_SDK,
        "webcast_version_code": WEBCAST_SDK,
        "manifest_version_code": str(profile.get("manifestVersionCode", "400701")),
        "app_type": "normal",
        "iid": iid,
        "channel": str(profile.get("channel", "googleplay")),
        "device_type": str(b.get("model", "PGZ110")),
        "language": "zh",
        "resolution": str(d.get("resolution", "1080*2246")).replace("x", "*"),
        "openudid": str(ids.get("openudid") or profile.get("openudid", "")),
        "update_version_code": str(profile.get("updateVersionCode", "40709900")),
        "os_api": str(b.get("sdk_int", "35")),
        "dpi": str(d.get("dpi", "480")),
        "ac": "wifi",
        "device_id": did,
        "mcc_mnc": "46000",
        "os_version": str(b.get("release", "15")),
        "version_code": str(profile.get("versionCode", "400701")),
        "app_name": "aweme",
        "version_name": str(profile.get("appVersion", "40.7.0")),
        "device_brand": str(b.get("brand", "OnePlus")),
        "ssmix": "a",
        "device_platform": "android",
        "aid": str(profile.get("appId", "1128")),
        "cdid": str(ids.get("cdid") or profile.get("cdid", "")),
        "room_id": str(room_id),
        "rid": str(room_id),
        "is_login": "0",
        "identity": "audience",
        "live_reason": "user",
        "enter_source": "live_merge-live_cover",
        "enter_type": "click",
        "_rticket": str(int(time.time() * 1000)),
    }


def signed_request(
    host: str,
    path: str,
    params: dict[str, str],
    profile: dict,
    method: str = "POST",
    proxies: dict | None = None,
    device_token: str = "",
) -> requests.Response:
    body = urllib.parse.urlencode(params)
    url = f"{host}{path}?{body}"
    did, iid = params.get("device_id", ""), params.get("iid", "")
    headers = {
        "User-Agent": profile.get("userAgent", "Dalvik/2.1.0"),
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept-Encoding": "gzip",
        "x-ss-dp": str(profile.get("appId", "1128")),
        "sdk-version": "2",
    }
    if device_token:
        headers["x-tt-token"] = device_token
        headers["x-tt-dt"] = device_token
    _trace("sign begin %s %s" % (method, path[:40]))
    headers.update(sign(url, body if method.upper() == "POST" else "", did, iid))
    _trace("sign ok %s" % path[:40])
    if method.upper() == "GET":
        _trace("http get %s" % host)
        return requests.get(
            url,
            headers=headers,
            timeout=(10, 25),
            proxies=proxies or {},
            allow_redirects=True,
        )
    return requests.post(
        f"{host}{path}",
        data=body,
        params=params,
        headers=headers,
        timeout=(10, 25),
        proxies=proxies or {},
        allow_redirects=True,
    )


def resolve_room_id(room: str) -> str:
    room = str(room).strip()
    if room.isdigit() and len(room) > 12:
        return room
    if "douyin.com" in room or room.startswith("http"):
        url = room if room.startswith("http") else f"https://{room}"
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 15)"}, timeout=20, allow_redirects=True)
        final = r.url or ""
        m = re.search(r"/(?:reflow|webcast)/(\d{15,})", final) or re.search(r"room_id=(\d{15,})", final)
        if m:
            return m.group(1)
        text = r.text or ""
        m = re.search(r'\\"roomId\\"\s*:\s*\\"(\d+)\\"', text) or re.search(r'"roomId"\s*:\s*"(\d+)"', text)
        if m:
            return m.group(1)
        raise RuntimeError(f"cannot resolve room_id from {url}")
    url = f"https://live.douyin.com/{room}"
    r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
    m = re.search(r'\\"roomId\\"\s*:\s*\\"(\d+)\\"', r.text or "") or re.search(r'"roomId"\s*:\s*"(\d+)"', r.text or "")
    if not m:
        raise RuntimeError(f"cannot resolve room_id from {room}")
    return m.group(1)


def pick_live_room() -> str:
    feed = requests.get(
        "https://live.douyin.com/webcast/feed/",
        params={"aid": "6383", "device_platform": "web", "count": "8"},
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=20,
    ).json()
    for item in feed.get("data") or []:
        data = item.get("data") or item
        rid = str(data.get("id_str") or data.get("id") or "")
        if rid and data.get("status") == 2:
            print(f"[pick] room_id={rid} viewers={data.get('user_count')}")
            return rid
    raise RuntimeError("no live room in feed")


def enter_room(profile: dict, room_id: str, ids: dict | None = None, proxies: dict | None = None) -> dict:
    params = base_params(profile, room_id, ids)
    token = str((ids or {}).get("device_token") or "")
    last = None
    for host in WEBCAST_HOSTS:
        try:
            r = signed_request(host, "/webcast/room/enter/", params, profile, "POST", proxies=proxies, device_token=token)
            text = (r.text or "").strip()
            print(f"[enter] {host} http={r.status_code} len={len(text)}")
            if r.status_code == 200 and text and text != "{}":
                try:
                    body = r.json()
                    if body.get("data") or body.get("status_code") == 0:
                        return {"ok": True, "host": host, "response": body}
                except Exception:
                    return {"ok": True, "host": host, "response_text": text}
            reason = "empty_body"
            if r.status_code != 200:
                reason = f"http_{r.status_code}"
            last = {"host": host, "status": r.status_code, "body": text[:300], "reason": reason}
        except Exception as e:
            print(f"[enter] {host} error={e}")
            last = {"host": host, "error": str(e), "reason": "exception"}
    return {"ok": False, "last": last, "reason": (last or {}).get("reason", "enter_failed")}


def ping_room(profile: dict, room_id: str, ids: dict | None = None, proxies: dict | None = None) -> dict:
    params = base_params(profile, room_id, ids)
    for host in WEBCAST_HOSTS:
        try:
            r = signed_request(host, PING_PATH, params, profile, "GET", proxies=proxies)
            text = (r.text or "").strip()
            print(f"[ping] {host} http={r.status_code} body={text[:200]}")
            if r.status_code == 200 and text:
                body = r.json()
                if body.get("status_code") == 0:
                    next_ping = int(((body.get("data") or {}).get("next_ping")) or 60)
                    return {"ok": True, "host": host, "response": body, "next_ping": next_ping}
        except Exception as e:
            print(f"[ping] {host} error={e}")
    return {"ok": False}


def watch(profile: dict, room_id: str, duration: int = 300, interval: int = 0, ids: dict | None = None) -> None:
    enter = enter_room(profile, room_id, ids)
    if not enter.get("ok"):
        raise RuntimeError(f"enter failed: {enter}")
    end = time.time() + max(duration, 10)
    n = 0
    wait = interval or 60
    while time.time() < end:
        n += 1
        ping = ping_room(profile, room_id, ids)
        if ping.get("ok"):
            wait = max(10, min(int(ping.get("next_ping") or wait), 300))
        time.sleep(min(wait, max(5, int(end - time.time()))))
    print(f"[watch] done pings={n}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Douyin Android live audience (no cookie)")
    ap.add_argument("--profile", default=str(ROOT / "config/device_profile.json"))
    ap.add_argument("--room", default="", help="web_rid or room_id")
    ap.add_argument("--device-id", default="")
    ap.add_argument("--install-id", default="")
    ap.add_argument("--enter-only", action="store_true")
    ap.add_argument("--watch", type=int, default=0, help="keep audience ping N seconds")
    ap.add_argument("--ping-interval", type=int, default=0, help="override ping interval seconds")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    profile = load_json(args.profile)
    ids = {}
    if args.device_id:
        ids["device_id"] = args.device_id
    if args.install_id:
        ids["install_id"] = args.install_id
    room = args.room or pick_live_room()
    room_id = room if room.isdigit() and len(room) > 12 else resolve_room_id(room)
    print(f"[room] id={room_id}")
    if args.watch > 0:
        watch(profile, room_id, duration=args.watch, interval=args.ping_interval, ids=ids or None)
        return 0
    res = enter_room(profile, room_id, ids or None)
    if not args.enter_only:
        ping_room(profile, room_id, ids or None)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
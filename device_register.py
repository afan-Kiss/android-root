#!/usr/bin/env python3
"""Platform device_register: gzip(JSON) -> pure ttEncrypt -> POST /service/2/device_register/"""
from __future__ import annotations
import argparse, gzip, json, os, random, sys, time, uuid
from pathlib import Path
import requests
ROOT = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))
_sp = str(ROOT / "scripts")
if _sp not in sys.path:
    sys.path.insert(0, _sp)
from profile_tools import load_json
from vendor.ttencrypt import encrypt_payload_pure
APPKEY, SIG_HASH = "57bfa27c67e58e7d923328d3", "aea615ab910015038f73c47e45d21466"
RELEASE_BUILD, GIT_HASH = "850a022_20261008", "850a022"
HOSTS = (
    "https://aweme.snssdk.com",
    "https://ib.snssdk.com",
    "https://log.snssdk.com",
    "https://log3-misc.amemv.com",
    "https://log3-misc-hl.amemv.com",
)

def _hex(n=16):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))

def new_ids():
    ou = _hex(16)
    return {
        "openudid": ou, "android_id": ou, "clientudid": str(uuid.uuid4()), "cdid": str(uuid.uuid4()),
        "req_id": str(uuid.uuid4()), "serial_number": _hex(8), "build_serial": _hex(8),
        "mc": ":".join(_hex(2) for _ in range(6)).upper(),
        "udid": "".join(random.choice("0123456789") for _ in range(15)),
        "google_aid": str(uuid.uuid4()),
    }

def payload(profile, ids):
    b, d = profile.get("build") or {}, profile.get("display") or {}
    now = int(time.time() * 1000)
    res = str(d.get("resolution", "1080x2246")).replace("*", "x")
    h = {
        "display_name": "\u6296\u97f3", "update_version_code": int(profile.get("updateVersionCode", 40709900)),
        "manifest_version_code": int(profile.get("manifestVersionCode", 400701)), "app_version_minor": "",
        "aid": int(profile.get("appId", 1128)), "channel": profile.get("channel", "googleplay"), "appkey": APPKEY,
        "package": profile.get("packageName", "com.ss.android.ugc.aweme"), "app_version": profile.get("appVersion", "40.7.0"),
        "version_code": int(profile.get("versionCode", 400701)), "sdk_version": "400701",
        "sdk_target_version": int(b.get("sdk_int", 35)), "git_hash": GIT_HASH, "os": "Android",
        "os_version": str(b.get("release", "15")), "os_api": int(b.get("sdk_int", 35)),
        "device_model": b.get("model", "PGZ110"), "device_brand": b.get("brand", "OnePlus"),
        "device_manufacturer": b.get("manufacturer", "OnePlus"), "cpu_abi": profile.get("hostAbi", "arm64-v8a"),
        "build_serial": ids["build_serial"], "release_build": RELEASE_BUILD, "density_dpi": int(d.get("dpi", 480)),
        "display_density": "xhdpi", "resolution": res, "language": "zh", "timezone": 8, "access": "wifi",
        "not_request_sender": 0, "carrier": "\u4e2d\u56fd\u79fb\u52a8", "mcc_mnc": "46000", "rom": b.get("brand", "OnePlus"),
        "rom_version": b.get("display", "release-keys"), "mc": ids["mc"], "udid": ids["udid"],
        "cdid": ids["cdid"], "sig_hash": SIG_HASH,
        "google_aid": ids["google_aid"], "openudid": ids["openudid"], "clientudid": ids["clientudid"],
        "serial_number": ids["serial_number"], "sim_serial_number": [], "region": "CN", "tz_name": "Asia/Shanghai",
        "tz_offset": 28800, "sim_region": "cn", "oaid_may_support": True, "req_id": ids["req_id"],
        "custom": {"filter_warn": 0, "web_ua": profile.get("userAgent", "")},
        "apk_first_install_time": now - random.randint(60000, 3600000), "is_system_app": 0, "sdk_flavor": "china",
        "device_id": "", "install_id": "",
    }
    return {"magic_tag": "ss_app_log", "header": h, "_gen_time": now}

def query(profile, ids):
    b, d = profile.get("build") or {}, profile.get("display") or {}
    ts = int(time.time())
    return {
        "tt_data": "a", "ac": "wifi", "channel": profile.get("channel", "googleplay"), "aid": profile.get("appId", "1128"),
        "app_name": "aweme", "version_code": str(profile.get("versionCode", "400701")),
        "version_name": profile.get("appVersion", "40.7.0"), "device_platform": "android", "ssmix": "a", "os": "android",
        "device_type": b.get("model", "PGZ110"), "device_brand": b.get("brand", "OnePlus"), "language": "zh",
        "os_api": str(b.get("sdk_int", 35)), "os_version": str(b.get("release", "15")), "openudid": ids["openudid"],
        "manifest_version_code": str(profile.get("manifestVersionCode", "400701")),
        "resolution": str(d.get("resolution", "1080x2246")).replace("x", "*"), "dpi": str(d.get("dpi", 480)),
        "update_version_code": str(profile.get("updateVersionCode", "40709900")),
        "mcc_mnc": "46000", "timezone": "8", "timezone_offset": "28800", "timezone_name": "Asia/Shanghai",
        "first_launch_timestamp": str(ts), "cpu_support64": "true", "host_abi": profile.get("hostAbi", "arm64-v8a"),
        "is_guest_mode": "0", "app_type": "normal", "is_pad": "0", "ts": str(ts), "region": "CN",
        "_rticket": str(int(time.time() * 1000)), "device_id": "", "iid": "", "cdid": ids["cdid"],
    }

def tt_encrypt(gz: bytes) -> bytes:
    return encrypt_payload_pure(gz, timestamp_sec=int(time.time()))

def _is_zero_id_response(data: dict) -> bool:
    did = str(data.get("device_id_str") or data.get("device_id") or "")
    return did in ("", "0", "None")

def verify_device(device_id: str, install_id: str, timeout: int = 15) -> dict:
    """Lightweight post-register check via app_alert_check."""
    r = requests.get(
        "https://aweme.snssdk.com/service/2/app_alert_check/",
        params={"device_id": device_id, "install_id": install_id, "aid": "1128", "version_code": "400701"},
        timeout=timeout,
    )
    body = r.json() if r.text.strip() else {}
    return {"ok": r.status_code == 200 and body.get("message") == "success", "status": r.status_code, "body": body}

def register_once(profile, dry_run=False, plaintext=False, timeout=30, proxies=None):
    ids = new_ids()
    pl = payload(profile, ids)
    raw = json.dumps(pl, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    gz = gzip.compress(raw)
    if dry_run:
        enc = tt_encrypt(gz)
        return {"dry_run": True, "json_bytes": len(raw), "gzip_bytes": len(gz), "encrypt_bytes": len(enc),
                "encrypt_magic": enc[:6].hex(), "openudid": ids["openudid"]}
    q = query(profile, ids)
    hdr = {"User-Agent": profile.get("userAgent", "Dalvik/2.1.0"), "Accept-Encoding": "gzip",
           "sdk-version": "2", "x-ss-dp": str(profile.get("appId", "1128"))}
    body = raw if plaintext else tt_encrypt(gz)
    hdr["Content-Type"] = "application/json; charset=utf-8" if plaintext else "application/octet-stream;tt-data=a"
    err = None
    for host in HOSTS:
        try:
            r = requests.post(host + "/service/2/device_register/", params=q, data=body, headers=hdr, timeout=timeout, proxies=proxies)
            if r.status_code != 200 or not r.text.strip():
                err = f"{host} HTTP {r.status_code}"; continue
            data = r.json()
            did = str(data.get("device_id_str") or data.get("device_id") or "")
            iid = str(data.get("install_id_str") or data.get("install_id") or "")
            if not did or did in ("0", "None") or not iid or iid in ("0", "None"):
                if _is_zero_id_response(data):
                    err = f"{host} rate_limited_or_rejected: device_id=0"
                else:
                    err = f"{host} invalid: {r.text[:300]}"
                continue
            return {"ok": True, "host": host, "device_id": did, "install_id": iid,
                    "device_token": data.get("device_token"), "new_user": data.get("new_user"),
                    "plaintext": plaintext, "raw": data, **ids}
        except Exception as e:
            err = f"{host} {e}"
    if err and "rate_limited_or_rejected" in err:
        raise RuntimeError("device_id=0 on all hosts (rate_limited_or_rejected)")
    raise RuntimeError(err or "failed")

def register_with_retry(profile, retries: int = 3, delay: float = 30.0, **kwargs) -> dict:
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            return register_once(profile, **kwargs)
        except RuntimeError as e:
            last_err = e
            retryable = "rate_limited_or_rejected" in str(e) or "device_id=0" in str(e)
            if attempt >= retries or not retryable:
                raise
            print(f"[retry] {attempt}/{retries} failed ({e}), wait {delay:.0f}s ...", file=sys.stderr)
            time.sleep(delay)
    raise RuntimeError(last_err or "failed")

def save_registration(path: Path, res: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "device_id": res["device_id"], "install_id": res["install_id"],
        "device_token": res.get("device_token"), "new_user": res.get("new_user"),
        "host": res.get("host"), "openudid": res.get("openudid"), "cdid": res.get("cdid"),
        "saved_at": int(time.time()),
    }
    rows = []
    if path.exists():
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(rows, list):
                rows = [rows]
        except Exception:
            rows = []
    rows.append(record)
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description="Douyin Android device_register")
    ap.add_argument("--profile", default=str(ROOT / "config/device_profile.json"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--plaintext", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--retry", type=int, default=1, help="attempts on rate limit (default 1)")
    ap.add_argument("--delay", type=float, default=30.0, help="seconds between retries")
    ap.add_argument("--save", default="", help="append successful registration to JSON file")
    ap.add_argument("--verify", action="store_true", help="run app_alert_check after register")
    args = ap.parse_args()
    profile = load_json(args.profile)
    try:
        if args.retry > 1:
            res = register_with_retry(profile, retries=args.retry, delay=args.delay,
                                      dry_run=args.dry_run, plaintext=args.plaintext)
        else:
            res = register_once(profile, dry_run=args.dry_run, plaintext=args.plaintext)
    except Exception as e:
        print("FAIL:", e, file=sys.stderr); return 1
    if not res.get("dry_run"):
        if args.verify:
            v = verify_device(res["device_id"], res["install_id"])
            res["verified"] = v
            if not v.get("ok"):
                print("WARN: verify failed:", v, file=sys.stderr)
        if args.save:
            save_registration(Path(args.save), res)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    elif res.get("dry_run"):
        print(f"dry_run json={res['json_bytes']} gzip={res['gzip_bytes']} enc={res['encrypt_bytes']} magic={res['encrypt_magic']}")
    else:
        print(f"OK device_id={res['device_id']} install_id={res['install_id']} new_user={res.get('new_user')} host={res['host']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
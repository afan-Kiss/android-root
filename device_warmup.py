#!/usr/bin/env python3
"""Post device_register warmup: activate + app_log + log_settings + mssdk + config."""
from __future__ import annotations
import gzip, json, time, uuid, urllib.parse
from datetime import datetime
import requests
from device_register import query, tt_encrypt, verify_device

APP_LOG_HOSTS = (
    "https://log3-misc.amemv.com",
    "https://log.snssdk.com",
    "https://log3-misc-hl.amemv.com",
)
LOG_SETTINGS_HOSTS = ("https://log.snssdk.com", "https://log3-misc.amemv.com")
MSSDK_LC_ID = "1588093228"
API_HOST = "https://api5-normal.amemv.com"


def _header(profile: dict, reg: dict) -> dict:
    b, d = profile.get("build") or {}, profile.get("display") or {}
    res = str(d.get("resolution", "1080x2246")).replace("*", "x")
    now = int(time.time() * 1000)
    return {
        "display_name": "\u6296\u97f3",
        "update_version_code": int(profile.get("updateVersionCode", 40709900)),
        "manifest_version_code": int(profile.get("manifestVersionCode", 400701)),
        "aid": int(profile.get("appId", 1128)),
        "channel": profile.get("channel", "googleplay"),
        "package": profile.get("packageName", "com.ss.android.ugc.aweme"),
        "app_version": profile.get("appVersion", "40.7.0"),
        "version_code": int(profile.get("versionCode", 400701)),
        "sdk_version": "400701",
        "os": "Android",
        "os_version": str(b.get("release", "15")),
        "os_api": int(b.get("sdk_int", 35)),
        "device_model": b.get("model", "PGZ110"),
        "device_brand": b.get("brand", "OnePlus"),
        "device_manufacturer": b.get("manufacturer", "OnePlus"),
        "cpu_abi": profile.get("hostAbi", "arm64-v8a"),
        "density_dpi": int(d.get("dpi", 480)),
        "display_density": "xhdpi",
        "resolution": res,
        "language": "zh",
        "timezone": 8,
        "access": "wifi",
        "carrier": "\u4e2d\u56fd\u79fb\u52a8",
        "mcc_mnc": "46000",
        "rom": b.get("brand", "OnePlus"),
        "rom_version": b.get("display", "release-keys"),
        "cdid": reg.get("cdid", ""),
        "openudid": reg.get("openudid", ""),
        "clientudid": reg.get("clientudid", ""),
        "serial_number": reg.get("serial_number", ""),
        "build_serial": reg.get("build_serial", ""),
        "region": "CN",
        "tz_name": "Asia/Shanghai",
        "tz_offset": 28800,
        "sim_region": "cn",
        "device_platform": "android",
        "device_id": str(reg.get("device_id", "")),
        "install_id": str(reg.get("install_id", "")),
        "custom": {"filter_warn": 0, "web_ua": profile.get("userAgent", "")},
        "apk_first_install_time": now - 3600000,
    }


def app_log_body(profile: dict, reg: dict, label: str = "cold_launch") -> dict:
    session_id = str(uuid.uuid4())
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "magic_tag": "ss_app_log",
        "header": _header(profile, reg),
        "launch": [{"datetime": ts, "session_id": session_id}],
        "event": [{"nt": 4, "category": "umeng", "tag": "launch", "label": label,
                   "session_id": session_id, "datetime": ts, "event_id": 1}],
        "_gen_time": int(time.time() * 1000),
    }


def _base_q(profile: dict, reg: dict) -> dict:
    ids = {
        "openudid": reg.get("openudid", ""),
        "cdid": reg.get("cdid", ""),
        "clientudid": reg.get("clientudid", str(uuid.uuid4())),
        "serial_number": reg.get("serial_number", ""),
        "build_serial": reg.get("build_serial", ""),
    }
    q = query(profile, ids)
    q["device_id"] = str(reg.get("device_id", ""))
    q["iid"] = str(reg.get("install_id", ""))
    return q


def activate_device(reg: dict, profile: dict | None = None, proxies=None, timeout: int = 15) -> dict:
    did, iid = str(reg.get("device_id", "")), str(reg.get("install_id", ""))
    if not did or not iid:
        return {"ok": False, "error": "missing ids"}
    return verify_device(did, iid, timeout=timeout)


def log_settings(reg: dict, profile: dict, proxies=None, timeout: int = 15) -> dict:
    q = _base_q(profile, reg)
    hdr = {"User-Agent": profile.get("userAgent", "Dalvik/2.1.0"), "Accept-Encoding": "gzip"}
    for host in LOG_SETTINGS_HOSTS:
        try:
            r = requests.get(host + "/service/2/log_settings/", params=q, headers=hdr,
                             timeout=timeout, proxies=proxies)
            if r.status_code == 200 and r.content:
                return {"ok": True, "host": host, "len": len(r.content)}
        except Exception as e:
            last = str(e)
    return {"ok": False, "error": last if "last" in dir() else "failed"}


def app_log_once(profile: dict, reg: dict, proxies=None, timeout: int = 30, label: str = "cold_launch") -> dict:
    raw = json.dumps(app_log_body(profile, reg, label=label), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    body = tt_encrypt(gzip.compress(raw))
    q = _base_q(profile, reg)
    hdr = {"User-Agent": profile.get("userAgent", "Dalvik/2.1.0"), "Accept-Encoding": "gzip",
           "sdk-version": "2", "x-ss-dp": str(profile.get("appId", "1128")),
           "Content-Type": "application/octet-stream;tt-data=a"}
    last = None
    for host in APP_LOG_HOSTS:
        try:
            r = requests.post(host + "/service/2/app_log/", params=q, data=body, headers=hdr,
                              timeout=timeout, proxies=proxies)
            last = {"host": host, "status": r.status_code}
            if r.status_code == 200:
                return {"ok": True, **last}
        except Exception as e:
            last = {"host": host, "error": str(e)}
    return {"ok": False, "last": last}


def warmup_device(profile: dict, reg: dict, proxies=None, timeout: int = 30) -> dict:
    return app_log_once(profile, reg, proxies=proxies, timeout=timeout)


def mssdk_prime(reg: dict, profile: dict, proxies=None, timeout: int = 20) -> dict:
    did, iid = str(reg.get("device_id", "")), str(reg.get("install_id", ""))
    ver = profile.get("appVersion", "40.7.0")
    base_q = (
        f"lc_id={MSSDK_LC_ID}&platform=android&device_platform=android&aid=1128"
        f"&device_id={did}&iid={iid}&version_name={ver}"
    )
    hdr = {"User-Agent": profile.get("userAgent", "Dalvik/2.1.0"),
           "Content-Type": "application/octet-stream", "Accept-Encoding": "gzip"}
    out = {}
    for name, path in (("get_token", "/sdi/get_token"), ("ri_report", "/ri/report")):
        url = f"https://mssdk.bytedance.com{path}?{base_q}"
        try:
            r = requests.post(url, data=b"", headers=hdr, timeout=timeout, proxies=proxies)
            out[name] = {"status": r.status_code, "len": len(r.content)}
        except Exception as e:
            out[name] = {"error": str(e)}
    return out


def config_get(profile: dict, reg: dict, proxies=None, timeout: int = 20) -> dict:
    did, iid = str(reg.get("device_id", "")), str(reg.get("install_id", ""))
    params = {
        "aid": "1128", "device_id": did, "iid": iid,
        "version_name": profile.get("appVersion", "40.7.0"),
        "device_platform": "android", "ac": "wifi",
    }
    hdr = {"User-Agent": profile.get("userAgent", "Dalvik/2.1.0"), "x-ss-dp": "1128"}
    try:
        from live_audience import sign
        url = API_HOST + "/aweme/v1/config/get/?" + urllib.parse.urlencode(params)
        hdr.update(sign(url, "", did, iid))
    except Exception as e:
        return {"ok": False, "error": "sign unavailable: %s" % e}
    try:
        r = requests.get(API_HOST + "/aweme/v1/config/get/", params=params, headers=hdr,
                         timeout=timeout, proxies=proxies)
        return {"ok": r.status_code == 200 and len(r.content) > 0, "status": r.status_code, "len": len(r.content)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def full_warmup(profile: dict, reg: dict, proxies=None, app_log_rounds: int = 3, pause: float = 1.5) -> dict:
    steps = {}
    steps["activate"] = activate_device(reg, profile, proxies=proxies)
    steps["log_settings"] = log_settings(reg, profile, proxies=proxies)
    logs = []
    for i in range(max(1, app_log_rounds)):
        label = "cold_launch" if i == 0 else "warm_launch"
        logs.append(app_log_once(profile, reg, proxies=proxies, label=label))
        time.sleep(pause)
    steps["app_log"] = logs
    steps["config_get"] = config_get(profile, reg, proxies=proxies)
    steps["mssdk"] = mssdk_prime(reg, profile, proxies=proxies)
    ok = steps["activate"].get("ok") and any(x.get("ok") for x in logs)
    return {"ok": ok, "steps": steps}


def merge_reg_profile(profile: dict, reg: dict) -> dict:
    p = json.loads(json.dumps(profile))
    p["deviceId"] = str(reg["device_id"])
    p["installId"] = str(reg["install_id"])
    p["openudid"] = str(reg.get("openudid", ""))
    p["androidId"] = str(reg.get("openudid", ""))
    if reg.get("cdid"):
        p["cdid"] = str(reg["cdid"])
    return p
"""MSSDK get_token HTTP helpers (post wire body captured from phone / unidbg)."""
from __future__ import annotations

import re
from pathlib import Path

import requests

ROOT = Path(r"E:\douyin-android-sign")
WIRE_BIN = ROOT / "config/mssdk_wire_body.bin"
MSSDK_LC_ID = "1588093228"


def build_get_token_url(reg: dict, profile: dict) -> str:
    did = str(reg.get("device_id", ""))
    iid = str(reg.get("install_id", ""))
    ver = str(profile.get("appVersion") or "40.7.0")
    return (
        f"https://mssdk.bytedance.com/sdi/get_token?lc_id={MSSDK_LC_ID}"
        f"&platform=android&device_platform=android&aid=1128"
        f"&device_id={did}&iid={iid}&version_name={ver}"
    )


def post_get_token(
    reg: dict,
    profile: dict,
    body: bytes,
    proxies=None,
    timeout: int = 25,
    sign_headers: dict | None = None,
) -> dict:
    url = build_get_token_url(reg, profile)
    hdr = {
        "User-Agent": profile.get("userAgent", "Dalvik/2.1.0"),
        "Content-Type": "application/octet-stream",
        "Accept-Encoding": "gzip",
    }
    for k, v in (sign_headers or {}).items():
        if k and v:
            hdr[str(k)] = str(v)
    try:
        r = requests.post(url, data=body, headers=hdr, timeout=timeout, proxies=proxies)
        return {"ok": r.status_code == 200 and len(r.content) > 0, "status": r.status_code, "body": r.content}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def extract_hex_sdi_from_response(data: bytes) -> str:
    if not data:
        return ""
    hx = data.hex()
    for m in re.finditer(r"[0-9a-f]{80,128}", hx):
        cand = m.group(0)
        if not cand.startswith("7b"):
            return cand[:80] if len(cand) >= 80 else cand
    return ""


def try_wire_file_post(reg: dict, profile: dict, proxies=None) -> dict:
    if not WIRE_BIN.is_file():
        return {"ok": False, "reason": "no_wire_body"}
    body = WIRE_BIN.read_bytes()
    if len(body) < 16:
        return {"ok": False, "reason": "wire_too_short"}
    resp = post_get_token(reg, profile, body, proxies=proxies)
    token = extract_hex_sdi_from_response(resp.get("body") or b"")
    return {**resp, "sdi_hex": token, "wire_len": len(body)}
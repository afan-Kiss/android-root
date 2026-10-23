"""Protobuf helpers for MSSDK get_token inner device message."""
from __future__ import annotations
import time
import uuid

NOTSET = "!notset!"

def _varint(n: int) -> bytes:
    if n < 0:
        raise ValueError(n)
    if n == 0:
        return b"\x00"
    parts = []
    while n > 127:
        parts.append(bytes([(n & 0x7f) | 0x80]))
        n >>= 7
    parts.append(bytes([n]))
    return b"".join(parts)

def _tag(field_no: int, wire_type: int) -> bytes:
    return _varint((field_no << 3) | (wire_type & 7))

def _string_field(field_no: int, value: str) -> bytes:
    b = value.encode("utf-8")
    return _tag(field_no, 2) + _varint(len(b)) + b

def _bytes_field(field_no: int, data: bytes) -> bytes:
    return _tag(field_no, 2) + _varint(len(data)) + data

def _varint_field(field_no: int, value: int) -> bytes:
    return _tag(field_no, 0) + _varint(value)

def _submessage(field_no: int, body: bytes) -> bytes:
    return _tag(field_no, 2) + _varint(len(body)) + body

def _resolution_str(d: dict) -> str:
    return str(d.get("resolution", "1080*2246")).replace("x", "*")

def _boot_id(profile: dict, reg: dict) -> str:
    for key in ("boot_id", "boot_id_str"):
        v = reg.get(key) or profile.get(key)
        if v:
            return str(v)
    raw = str(reg.get("clientudid") or profile.get("clientudid") or "").replace("-", "")
    if len(raw) >= 32:
        return raw[:32]
    return str(uuid.uuid4()).replace("-", "")

def _media_drm_id(profile: dict, reg: dict) -> bytes:
    for key in ("media_drm_id", "mediaDrmId"):
        v = reg.get(key) or profile.get(key)
        if isinstance(v, str) and v:
            try:
                return bytes.fromhex(v)
            except ValueError:
                return v.encode("utf-8")
        if isinstance(v, (bytes, bytearray)):
            return bytes(v)
    seed = str(reg.get("openudid") or profile.get("openudid") or "android")
    return seed.encode("utf-8")[:44].ljust(44, b"\x00")

def build_inner_device_message(profile: dict, reg: dict, extras: dict | None = None) -> bytes:
    extras = extras or {}
    bld = profile.get("build") or {}
    disp = profile.get("display") or {}
    brand = str(bld.get("brand") or "OnePlus")
    model = str(bld.get("model") or "PGZ110")
    os_ver = str(bld.get("release") or "15")
    rom = str(bld.get("display") or "release-keys")
    dpi = int(disp.get("dpi") or 480)
    resolution = _resolution_str(disp)
    android_id = str(reg.get("openudid") or reg.get("android_id") or profile.get("androidId") or "")
    device_id = str(reg.get("device_id") or profile.get("deviceId") or "")
    install_id = str(reg.get("install_id") or profile.get("installId") or "")
    channel = str(profile.get("channel") or "googleplay")
    app_ver = str(profile.get("appVersion") or "40.7.0")
    sdk_ver = str(profile.get("sdkVersion") or "v04.10.04.01-bugfix")
    host_abi = str(profile.get("hostAbi") or "arm64-v8a")
    pkg = str(profile.get("packageName") or "com.ss.android.ugc.aweme")
    now_ms = int(extras.get("ts_ms") or time.time() * 1000)
    now_s = int(now_ms // 1000)
    tz_name = str(extras.get("tz_name") or "Asia/Shanghai")
    tz_off = int(extras.get("tz_offset") or 28800)
    lang = str(extras.get("language") or "zh")
    ip1 = str(extras.get("ip") or "172.19.154.167")
    ip2 = str(extras.get("ip2") or "172.19.154.254")
    boot = _boot_id(profile, reg)
    drm = _media_drm_id(profile, reg)
    parts: list[bytes] = []
    parts.append(_string_field(1, NOTSET))
    parts.append(_string_field(2, brand))
    parts.append(_string_field(3, model))
    parts.append(_string_field(4, NOTSET))
    parts.append(_string_field(5, "Android"))
    parts.append(_string_field(6, os_ver))
    parts.append(_string_field(7, resolution))
    parts.append(_varint_field(8, dpi))
    parts.append(_string_field(9, rom))
    parts.append(_varint_field(10, now_ms))
    parts.append(_string_field(11, lang))
    parts.append(_string_field(12, f"{tz_name},{tz_off}"))
    parts.append(_varint_field(13, 128))
    parts.append(_varint_field(14, now_s))
    parts.append(_varint_field(15, now_s))
    parts.append(_varint_field(16, now_s))
    parts.append(_string_field(17, NOTSET))
    parts.append(_string_field(20, NOTSET))
    parts.append(_string_field(21, android_id))
    parts.append(_string_field(22, NOTSET))
    parts.append(_string_field(23, NOTSET))
    parts.append(_bytes_field(24, drm))
    parts.append(_string_field(25, boot))
    parts.append(_varint_field(26, now_ms))
    parts.append(_string_field(45, ip1))
    parts.append(_string_field(46, ip2))
    parts.append(_varint_field(51, 620))
    parts.append(_varint_field(53, 106))
    parts.append(_string_field(56, '{"10.8.8.8","0.0.0.0"}'))
    parts.append(_varint_field(57, now_ms))
    parts.append(_varint_field(58, now_ms))
    parts.append(_string_field(85, str(extras.get("risk_id") or device_id[:16] or "AvesNBt21HE7iPNWFs1O16s7N")))
    parts.append(_string_field(86, "android"))
    parts.append(_string_field(87, sdk_ver))
    parts.append(_varint_field(88, int(profile.get("appId") or 1128)))
    parts.append(_string_field(89, app_ver))
    parts.append(_varint_field(90, int(device_id) if device_id.isdigit() else 0))
    parts.append(_string_field(91, install_id if install_id else "0000000000000000"))
    parts.append(_varint_field(92, now_ms))
    parts.append(_string_field(95, channel))
    parts.append(_string_field(96, host_abi))
    return b"".join(parts)

def build_outer_http_body(inner_plain: bytes, encrypted: bytes, device_id: str = "") -> bytes:
    parts = [_submessage(1, inner_plain), _bytes_field(6, encrypted)]
    did = str(device_id or "").strip()
    if did:
        parts.append(_string_field(8, did))
    return b"".join(parts)

def build_wire_body_from_encrypted(encrypted: bytes, inner_plain: bytes | None = None, device_id: str = "") -> bytes:
    if inner_plain is None:
        body = _bytes_field(6, encrypted)
        did = str(device_id or "").strip()
        if did:
            body += _string_field(8, did)
        return body
    return build_outer_http_body(inner_plain, encrypted, device_id=device_id)
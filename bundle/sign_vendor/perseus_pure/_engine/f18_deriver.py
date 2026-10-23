"""F18 capture-free dynamic48 (P2311 mill-less).

d48 = head32 || intern16
  intern16 = MD5(body) else EMPTY_STUB (x-ss-stub sentinel)
  head32   = SM3(ascii_hex(x-bd-client-key 64B) || unix_le4)

client-key 64B is device/session material (not in SO .rodata). Default pin is
the live X8DY9TBAYLH6W44P key (h2 half long-lived). Pass ``client_key64`` to
override.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any, Mapping

from ._sm3_impl import SM3

EMPTY_STUB = bytes.fromhex("06f8eb34f7e27c61bfe46cf700a1fce0")
F18_HEAD32_HEX64 = bytes.fromhex(
    "6a53ed2a173fa93d36563b370179232ef851cacde5ac990c2f354aa8b3e9f1eb"
    "84609486196db2930052c33d23c14e2f7ff21463cb983c77898fe100b34a3cd8"
)


def intern16_from_body(body: bytes | None) -> bytes:
    if not body:
        return EMPTY_STUB
    return hashlib.md5(body).digest()


def intern16_from_body_md5_hex(body_md5: str) -> bytes:
    text = (body_md5 or "").strip()
    if len(text) == 32:
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = b""
        if len(raw) == 16:
            return raw
    return EMPTY_STUB


def head32_from_unix(unix: int, hex64: bytes = F18_HEAD32_HEX64) -> bytes:
    if len(hex64) != 64:
        raise ValueError("hex64")
    msg = hex64.hex().encode("ascii") + struct.pack("<I", int(unix) & 0xFFFFFFFF)
    return SM3(msg).digest()


def derive_dynamic48(
    *,
    device_id: str,
    install_id: str = "",
    openudid: str = "",
    timestamp_sec: int,
    request_seq: int = 0,
    url: str = "",
    body_md5: str = "",
    client_key64: bytes | None = None,
    body: bytes | None = None,
) -> bytes:
    """48B F18 VM input: SM3(hex(client_key)||unix_le) || intern16."""
    del device_id, install_id, openudid, request_seq, url
    key = client_key64 if client_key64 is not None else F18_HEAD32_HEX64
    intern = intern16_from_body(body) if body is not None else intern16_from_body_md5_hex(body_md5)
    return head32_from_unix(int(timestamp_sec), key) + intern


@dataclass
class F18DerivationResult:
    dynamic48: bytes
    inputs: dict[str, Any]
    derivation_mode: str = "millless_sm3_clientkey_v1"
    capture_free: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "dynamic48_hex": self.dynamic48.hex(),
            "derivation_mode": self.derivation_mode,
            "capture_free": self.capture_free,
            "inputs": dict(self.inputs),
        }


def derive_f18_context(
    *,
    device_id: str,
    install_id: str = "",
    openudid: str = "",
    timestamp_sec: int,
    request_seq: int = 0,
    url: str = "",
    body: bytes | None = None,
    client_key64: bytes | None = None,
) -> F18DerivationResult:
    body_md5 = ""
    if body:
        body_md5 = hashlib.md5(body).hexdigest()
    key = client_key64 if client_key64 is not None else F18_HEAD32_HEX64
    dynamic48 = derive_dynamic48(
        device_id=device_id,
        install_id=install_id,
        openudid=openudid,
        timestamp_sec=timestamp_sec,
        request_seq=request_seq,
        url=url,
        body_md5=body_md5,
        body=body,
        client_key64=key,
    )
    return F18DerivationResult(
        dynamic48=dynamic48,
        inputs={
            "device_id": device_id,
            "install_id": install_id,
            "openudid": openudid,
            "timestamp_sec": int(timestamp_sec),
            "request_seq": int(request_seq),
            "url_prefix": url[:120],
            "body_md5": body_md5 or None,
            "client_key64_hex": key.hex(),
        },
        derivation_mode="millless_sm3_clientkey_v1",
    )


def dynamic48_for_runtime(
    runtime: Mapping[str, Any],
    *,
    device_id: str,
    timestamp_sec: int,
    url: str = "",
    body: bytes | None = None,
) -> bytes:
    """Bridge: use explicit dynamic48 if present, else derive."""
    explicit = runtime.get("dynamic48") or runtime.get("dynamic48_hex")
    if explicit:
        raw = bytes.fromhex(str(explicit)) if isinstance(explicit, str) else bytes(explicit)
        if len(raw) == 48:
            return raw
    install_id = str(runtime.get("install_id") or "")
    openudid = str(runtime.get("openudid") or "")
    seq = int(runtime.get("request_seq") or 0)
    raw_key = runtime.get("client_key64") or runtime.get("client_key64_hex")
    client_key64 = None
    if raw_key is not None:
        client_key64 = bytes.fromhex(str(raw_key)) if isinstance(raw_key, str) else bytes(raw_key)
    return derive_f18_context(
        device_id=device_id,
        install_id=install_id,
        openudid=openudid,
        timestamp_sec=timestamp_sec,
        request_seq=seq,
        url=url,
        body=body,
        client_key64=client_key64,
    ).dynamic48


__all__ = [
    "EMPTY_STUB",
    "F18_HEAD32_HEX64",
    "F18DerivationResult",
    "derive_dynamic48",
    "derive_f18_context",
    "dynamic48_for_runtime",
    "head32_from_unix",
    "intern16_from_body",
    "intern16_from_body_md5_hex",
]

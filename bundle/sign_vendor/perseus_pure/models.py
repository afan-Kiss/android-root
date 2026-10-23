from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any


def decode_bytes(value: Any, name: str) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise TypeError(f"{name} must be bytes or an encoded string")
    if value.startswith("hex:"):
        return bytes.fromhex(value[4:])
    if value.startswith("base64:"):
        return base64.b64decode(value[7:], validate=True)
    return value.encode("utf-8")


def _decode_fixed(value: Any, name: str, size: int) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        text = value.strip()
        if text.startswith("hex:"):
            raw = bytes.fromhex(text[4:])
        elif text.startswith("base64:"):
            raw = base64.b64decode(text[7:], validate=True)
        elif len(text) == size * 2:
            raw = bytes.fromhex(text)
        else:
            raise TypeError(f"{name} must be {size} bytes or {size * 2} hex chars")
    else:
        raise TypeError(f"{name} must be bytes or an encoded string")
    if len(raw) != size:
        raise ValueError(f"{name} must contain exactly {size} bytes, got {len(raw)}")
    return raw


def _decode_hex_blob(value: Any, name: str) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("hex:"):
            return bytes.fromhex(text[4:])
        if text.startswith("base64:"):
            return base64.b64decode(text[7:], validate=True)
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise TypeError(f"{name} must be hex or encoded bytes") from exc
    raise TypeError(f"{name} must be bytes or an encoded string")


def decode_client_key64(value: Any) -> bytes | None:
    """TTNet x-bd-client-key: 64 raw bytes, or 128 hex chars, or hex:/base64:."""
    if value is None:
        return None
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        text = value.strip()
        if text.startswith("hex:"):
            raw = bytes.fromhex(text[4:])
        elif text.startswith("base64:"):
            raw = base64.b64decode(text[7:], validate=True)
        elif len(text) == 128:
            raw = bytes.fromhex(text)
        else:
            raise TypeError("client_key64 must be 64 bytes or 128 hex chars")
    else:
        raise TypeError("client_key64 must be bytes or an encoded string")
    if len(raw) != 64:
        raise ValueError(f"client_key64 must contain exactly 64 bytes, got {len(raw)}")
    return raw


@dataclass(frozen=True)
class DeviceProfile:
    device_id: str
    app_version: str
    sec_device_token: str | None = None
    # 12B builder/session SHA1 input (SO+0x256738). NOT live proto field13.
    medusa_field13_input: bytes | None = None
    # Optional fallback 20B Medusa proto query_body_ts_hash (prefer RequestInput).
    medusa_query_body_ts_hash: bytes | None = None
    medusa_counters: dict[str, int] | None = None
    ticket_guard: dict[str, Any] | None = None
    medusa_cold_pure_v1: bool = False
    medusa_tab: list[int] | None = None
    medusa_tbl: int | None = None
    # TTNet ClientKeyManager 64B (x-bd-client-key). Server+Keva, not SO const.
    # F18 head32 = SM3(ascii_hex(this) || unix_le4). None → delivery pin.
    client_key64: bytes | None = None
    # 25-char MSSDK token for Medusa/Perseus proto f16. Not 151-char x-tt-dt.
    medusa_field16: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeviceProfile":
        return cls(
            device_id=str(data.get("device_id", "")),
            app_version=str(data.get("app_version", data.get("version_name", ""))),
            sec_device_token=data.get("sec_device_token"),
            medusa_field13_input=decode_bytes(data.get("medusa_field13_input"), "medusa_field13_input"),
            medusa_query_body_ts_hash=decode_bytes(
                data.get("medusa_query_body_ts_hash") or data.get("query_body_ts_hash"),
                "medusa_query_body_ts_hash",
            ),
            medusa_counters=data.get("medusa_counters"),
            ticket_guard=data.get("ticket_guard"),
            medusa_cold_pure_v1=bool(data.get("medusa_cold_pure_v1")),
            medusa_tab=data.get("medusa_tab") or data.get("tab"),
            medusa_tbl=None if data.get("medusa_tbl") is None else int(data.get("medusa_tbl")),
            client_key64=decode_client_key64(
                data.get("client_key64") or data.get("x_bd_client_key")
            ),
            medusa_field16=data.get("medusa_field16") or data.get("mssdk_token"),
        )


@dataclass(frozen=True)
class RequestInput:
    url: str
    body: bytes
    timestamp: int
    protobuf_chunk: bytes | None = None
    json_chunk: bytes | None = None
    raw_seed: bytes | None = None
    selector: int | None = None
    random_value: int | None = None
    transform_random: int | None = None
    xg_rand: int | None = None
    helios_rand: int | None = None
    ladon_raw: bytes | None = None
    medusa_rand: int | None = None
    medusa_hash_rand: int | None = None
    medusa_xm_rand: int | None = None
    medusa_random_mask: bytes | None = None
    medusa_header_extension: bytes | None = None
    # Live Medusa protobuf field13 (query_body_ts_hash), 20B. Prefer explicit
    # capture; or supply medusa_field13_closure / legacy seed_snaps material.
    # Not SHA1(medusa_field13_input). Leaves close from seed+gap or snaps.
    medusa_query_body_ts_hash: bytes | None = None
    # Preferred static-closure material for Medusa 20B (P2055 wired entry):
    #   - W path: w0,w1,w2,w3[,lag,f12/ts]
    #   - compose path: p148_pres8,p160_pres8,p150,p158,p148_m8c,p168_m8c,
    #                   tab[4], k|tbl, lag?, f12/ts/wall_ts?
    # Nested aliases such as preS8/snap84/snap88/snap8c or w{w0..w3} accepted.
    medusa_field13_closure: dict[str, Any] | None = None
    # Legacy alias kept for backward compatibility with old live-capture naming.
    medusa_field13_seed_snaps: dict[str, Any] | None = None
    medusa_cold_pure_v1: bool = False
    medusa_seed: bytes | None = None
    medusa_gap: bytes | None = None
    # Mill-less xor34-20B given first16 (assemble_from_w + last2 lag=1).
    medusa_first16: bytes | None = None
    # Mill workspace (≥168B): first16 = ws[136:152] xor ws[152:168] (P2151).
    medusa_mill_ws: bytes | None = None
    # w2=124 wide64 (≥64B): pack A||B then A xor B (P2165).
    medusa_wide64: bytes | None = None
    # Optional capture-free Perseus runtime boundaries. They are kept as
    # mappings here so RequestInput remains JSON-compatible; the engine
    # validates and materializes the VM contexts at the calculation boundary.
    f18_runtime: dict[str, Any] | None = None
    f19_runtime: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RequestInput":
        return cls(
            url=str(data["url"]),
            body=decode_bytes(data.get("body", b""), "body") or b"",
            timestamp=int(data["timestamp"]),
            protobuf_chunk=decode_bytes(data.get("protobuf_chunk"), "protobuf_chunk"),
            json_chunk=decode_bytes(data.get("json_chunk"), "json_chunk"),
            raw_seed=decode_bytes(data.get("raw_seed"), "raw_seed"),
            selector=None if data.get("selector") is None else int(data["selector"]),
            random_value=data.get("random_value"),
            transform_random=data.get("transform_random"),
            xg_rand=data.get("xg_rand"),
            helios_rand=data.get("helios_rand"),
            ladon_raw=decode_bytes(data.get("ladon_raw"), "ladon_raw"),
            medusa_rand=data.get("medusa_rand"),
            medusa_hash_rand=data.get("medusa_hash_rand"),
            medusa_xm_rand=data.get("medusa_xm_rand"),
            medusa_random_mask=decode_bytes(data.get("medusa_random_mask"), "medusa_random_mask"),
            medusa_header_extension=decode_bytes(data.get("medusa_header_extension"), "medusa_header_extension"),
            medusa_query_body_ts_hash=decode_bytes(
                data.get("medusa_query_body_ts_hash") or data.get("query_body_ts_hash"),
                "medusa_query_body_ts_hash",
            ),
            medusa_field13_closure=data.get("medusa_field13_closure")
            or data.get("field13_closure"),
            medusa_field13_seed_snaps=data.get("medusa_field13_seed_snaps")
            or data.get("field13_seed_snaps"),
            medusa_cold_pure_v1=bool(data.get("medusa_cold_pure_v1")),
            medusa_seed=decode_bytes(data.get("medusa_seed") or data.get("seed"), "medusa_seed"),
            medusa_gap=decode_bytes(data.get("medusa_gap") or data.get("gap"), "medusa_gap"),
            medusa_first16=_decode_fixed(
                data.get("medusa_first16") or data.get("first16"), "medusa_first16", 16
            ),
            medusa_mill_ws=_decode_hex_blob(
                data.get("medusa_mill_ws") or data.get("mill_ws"), "medusa_mill_ws"
            ),
            medusa_wide64=_decode_hex_blob(
                data.get("medusa_wide64") or data.get("wide64"), "medusa_wide64"
            ),
            f18_runtime=data.get("f18_runtime"),
            f19_runtime=data.get("f19_runtime"),
        )

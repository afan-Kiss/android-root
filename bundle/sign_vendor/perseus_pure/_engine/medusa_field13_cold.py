"""Medusa query_body_ts_hash (20B) cold-start derivation (Phase 8 / P2055).

Preferred path: seed + gap + SO TAB/tbl → closed leaf formulas → assemble.
Placeholder path: SHA256(device, ts) gap stand-in when seed/gap are absent.
The placeholder is deterministic, xor34-legal, and **not** live-exact.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .medusa_field13_assemble import (
    S5_PRIOR_FINAL,
    assemble_from_seed_snaps,
    k_from_ts,
    p178_hval_from_k_s5,
    rol32,
    C_S10,
    C_S9,
)
from .medusa_field13_leaves import (
    load_tab_from_so,
    load_tbl_from_so,
    snaps_from_seed_gap,
)

_TAB_SEED_SALT = "medusa-tab-v1"


def _device_seed(*parts: str) -> bytes:
    material = "|".join(p.strip() for p in parts if p and str(p).strip())
    return hashlib.sha256(material.encode("utf-8")).digest()


def derive_tbl(device_id: str, app_version: str = "") -> int:
    """Synthetic tbl u32 for k_from_ts when SO tbl is not imported."""
    seed = _device_seed(device_id, app_version, "medusa-tbl")
    return int.from_bytes(seed[:4], "little") | 0x80000000


def derive_tab(device_id: str) -> list[int]:
    """Synthetic TAB quad when SO+0xC3040 is not imported."""
    seed = _device_seed(device_id, _TAB_SEED_SALT)
    block = hashlib.sha256(seed + b":tab").digest()
    return [
        int.from_bytes(block[0:4], "little"),
        int.from_bytes(block[4:8], "little"),
        int.from_bytes(block[8:12], "little"),
        int.from_bytes(block[12:16], "little"),
    ]


def s26_from_x_ss_stub(x_ss_stub: str | bytes | None) -> int:
    """P336: s26/m54 = u32_le(x-ss-stub[12:16]); empty → 0xE0FCA100."""
    if not x_ss_stub:
        return 0xE0FCA100
    if isinstance(x_ss_stub, bytes):
        text = x_ss_stub.hex()
    else:
        text = str(x_ss_stub).strip()
    if len(text) < 16:
        return 0xE0FCA100
    try:
        return int.from_bytes(bytes.fromhex(text[12:16]), "little")
    except ValueError:
        return 0xE0FCA100


def _safe_k_from_ts(ts: int, tbl: int) -> int:
    try:
        return k_from_ts(int(ts), int(tbl))
    except KeyError:
        return 5


def _placeholder_gap_snaps(
    *,
    device_id: str,
    timestamp_sec: int,
    x_ss_stub: str | bytes | None,
    app_version: str,
    k: int,
    tbl: int,
) -> dict[str, int]:
    seed = _device_seed(device_id, str(timestamp_sec), "medusa-gap-v1")
    stream = hashlib.sha256(seed + b":gaps").digest()
    s26 = s26_from_x_ss_stub(x_ss_stub)
    p148_pres8 = int.from_bytes(stream[0:4], "little") ^ s26
    p160_pres8 = int.from_bytes(stream[4:8], "little") ^ rol32(s26, k & 31)
    p150 = (int.from_bytes(stream[8:12], "little") + rol32(C_S10, k)) & 0xFFFFFFFF
    p158 = (int.from_bytes(stream[12:16], "little") + rol32(C_S9, k)) & 0xFFFFFFFF
    p148_m8c = (p148_pres8 + int.from_bytes(stream[16:20], "little")) & 0xFFFFFFFF
    p168_m8c = (p160_pres8 + p178_hval_from_k_s5(k, S5_PRIOR_FINAL)) & 0xFFFFFFFF
    return {
        "k": k,
        "tbl": tbl,
        "p148_pres8": p148_pres8 & 0xFFFFFFFF,
        "p160_pres8": p160_pres8 & 0xFFFFFFFF,
        "p150": p150,
        "p158": p158,
        "p148_m8c": p148_m8c,
        "p168_m8c": p168_m8c,
        "s26": s26 & 0xFFFFFFFF,
        "s5_old": S5_PRIOR_FINAL,
        "derivation_mode": "cold_placeholder_v1",
    }


def derive_gap_snaps_cold(
    *,
    device_id: str,
    timestamp_sec: int,
    x_ss_stub: str | bytes | None = None,
    app_version: str = "",
    tab: list[int] | None = None,
    tbl: int | None = None,
    seed: bytes | None = None,
    gap: bytes | None = None,
    so: bytes | None = None,
    k: int | None = None,
) -> dict[str, int]:
    """Leaf snaps for seed-compose.

    With ``seed``+``gap``: closed P1857–P2055 formulas.
    Without: SHA256 placeholder (not live-exact).
    """
    if so is not None:
        if tab is None:
            tab = load_tab_from_so(so)
        if tbl is None:
            tbl = load_tbl_from_so(so)
    if tbl is None:
        tbl = derive_tbl(device_id, app_version)
    if k is None:
        k = _safe_k_from_ts(int(timestamp_sec), int(tbl))
    if seed is not None and gap is not None:
        snaps = snaps_from_seed_gap(seed, gap, k=k)
        snaps["tbl"] = int(tbl)
        snaps["derivation_mode"] = "seed_gap_v1"
        if tab is not None:
            snaps["tab0"] = tab[0]
        return snaps
    return _placeholder_gap_snaps(
        device_id=device_id,
        timestamp_sec=timestamp_sec,
        x_ss_stub=x_ss_stub,
        app_version=app_version,
        k=k,
        tbl=int(tbl),
    )


def derive_query_body_ts_hash_cold(
    *,
    device_id: str,
    timestamp_sec: int,
    body: bytes | None = None,
    x_ss_stub: str | bytes | None = None,
    app_version: str = "",
    lag: int = 1,
    tab: list[int] | None = None,
    tbl: int | None = None,
    seed: bytes | None = None,
    gap: bytes | None = None,
    so: bytes | None = None,
    k: int | None = None,
) -> bytes:
    """Assemble 20B Medusa field13 without an explicit closure dict."""
    stub = x_ss_stub
    if stub is None and body is not None:
        stub = hashlib.md5(body).hexdigest().upper()
    if so is not None and tab is None:
        tab = load_tab_from_so(so)
    gaps = derive_gap_snaps_cold(
        device_id=device_id,
        timestamp_sec=timestamp_sec,
        x_ss_stub=stub,
        app_version=app_version,
        tab=tab,
        tbl=tbl,
        seed=seed,
        gap=gap,
        so=so,
        k=k,
    )
    if tab is None:
        tab = derive_tab(device_id)
    return assemble_from_seed_snaps(
        p148_pres8=gaps["p148_pres8"],
        p160_pres8=gaps["p160_pres8"],
        p150=gaps["p150"],
        p158=gaps["p158"],
        p148_m8c=gaps["p148_m8c"],
        p168_m8c=gaps["p168_m8c"],
        k=gaps["k"],
        tab=tab,
        f12=int(timestamp_sec),
        lag=int(lag),
    )


def cold_closure_dict(
    *,
    device_id: str,
    timestamp_sec: int,
    body: bytes | None = None,
    x_ss_stub: str | bytes | None = None,
    app_version: str = "",
    tab: list[int] | None = None,
    tbl: int | None = None,
    seed: bytes | None = None,
    gap: bytes | None = None,
    so: bytes | None = None,
    k: int | None = None,
) -> dict[str, Any]:
    """Material dict compatible with assemble_from_material_dict / API closure."""
    stub = x_ss_stub
    if stub is None and body is not None:
        stub = hashlib.md5(body).hexdigest().upper()
    if so is not None:
        if tab is None:
            tab = load_tab_from_so(so)
        if tbl is None:
            tbl = load_tbl_from_so(so)
    gaps = derive_gap_snaps_cold(
        device_id=device_id,
        timestamp_sec=timestamp_sec,
        x_ss_stub=stub,
        app_version=app_version,
        tab=tab,
        tbl=tbl,
        seed=seed,
        gap=gap,
        so=so,
        k=k,
    )
    mode = str(gaps.get("derivation_mode") or "cold_pure_v1")
    return {
        "derivation_mode": mode,
        "k": gaps["k"],
        "tab": tab if tab is not None else derive_tab(device_id),
        "wall_ts": int(timestamp_sec),
        "lag": 1,
        "p148_pres8": gaps["p148_pres8"],
        "p160_pres8": gaps["p160_pres8"],
        "p150": gaps["p150"],
        "p158": gaps["p158"],
        "p148_m8c": gaps["p148_m8c"],
        "p168_m8c": gaps["p168_m8c"],
        "s5_old": S5_PRIOR_FINAL,
    }


__all__ = [
    "cold_closure_dict",
    "derive_gap_snaps_cold",
    "derive_query_body_ts_hash_cold",
    "derive_tab",
    "derive_tbl",
    "s26_from_x_ss_stub",
]

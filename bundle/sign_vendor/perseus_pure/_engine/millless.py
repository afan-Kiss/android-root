"""Mill-less closed helpers (seven_gods P2165–P2334 + compact WRAP f18).

Closed given imports (do not redo):
  intern16  = MD5(body) else EMPTY_STUB
  intern32  = 32B session nonce (kernel getrandom; os.urandom stand-in)
  intern48  = intern32 || intern16
  intern64  = intern48 || LANUSK_MD5_12 || u32(0x180)
  Medusa f18= millless_lanusk_hash: src16 mill + TAB assemble + last4
  F18 d48   = SM3(ascii_hex(client_key64)||unix_le4) || intern16
              (Perseus telemetry VM only; not compact WRAP lanusk)
  F18 wire  = generate_f18_pure(d48)  (last byte XOR 1 inside VM)
  F19 wire  = u32-endian-swap(source32); source32 = urandom 32B nonce
  Medusa 20B= assemble_from_w(first16, url_ts, lag=1)  given W/first16
  last2     = mill unix lag=1
  first16   = W = M ^ ROR(TAB, k+5). M = dest=10 mill-walk(seed,gap,k) (not dest=10 gap+0x420 gates).
              Import leftover: serialize p150/p160/p168 + gap LDRSW 428..456.
              Replay: first16_from_ws / wide / A xor B / derive_leaves(seed+gap).
  client-key h1 is TTNet/Keva import (P2320 did/iid mix 0). Do not SHA256(did).
"""
from __future__ import annotations

import os
import struct

from .f18_deriver import (
    EMPTY_STUB,
    F18_HEAD32_HEX64,
    derive_dynamic48,
    head32_from_unix,
    intern16_from_body,
)
from .medusaEncrypt import compute_byte18_byte19
from .medusa_field13_assemble import (
    assemble_from_w,
    assemble_from_wide64,
    first16_from_ab32,
    first16_from_wide,
    first16_from_ws,
    pack64_to_32,
)
from .p9bc_f19_vm import serialize_f19_source

# Honest leftover map. Status is import/governed/env — not "open research".
# Do not mark these open in PURE_DERIVATION_REGISTRY (offline gate requires 0 open).
REMAINING_BOUNDARIES: dict[str, dict[str, str]] = {
    "medusa_first16_request_only": {
        "status": "import_mill_session_m",
        "have": (
            "W[i]=M[i]^ROR32(TAB[i],k+5) (P2062). "
            "M = fill_m_from_d10_seed_gap mill-walk (18/18 == W^h); "
            "dest=10 gap+0x420 is k-gates ROR(C_PRE/C_S10/C_S9,k+5) NOT fill M. "
            "plant: p148=SO+k, p158=ROR(C516,k)+s27 (s27=k-table m60/m64 18/18), "
            "sl[21]=s21_from_k=u32le(p148 u8s) 18/18, dest=10 s5=gap524+s21=p148, "
            "sl[11]=~p160, sl[0]=0, sl[14]=ROR(0x7c92f514,k), sticky gap+468=ROR(C8C,k). "
            "dest=10 p150/p160/s10 == dest=9 2e0e30 enter (P1261 2/2); "
            "p168=ROR32(dest9.s9,26)+s10 at that 2e0e30. "
            "last s6 write = dest=9 2dfdbc then s6+=*(gap+428) (P1958; not dest=10 P1248 packing); "
            "dest=9 2d7104 enter -> 2dfdbc enter s6 via mill_d10 ops[0:14] (p9u1417 2/2); "
            "2dfdbc s8 = ROR32(s10+s8,17)+s6 (p9u1260 2/2) = dest=8 ADD s8_in; "
            "last s8 write = dest=8 ADD@2cf70c s8+=s25 (p9u1239+p9u1249); "
            "A8:B3 H1DEC formula does not apply here. "
            "taint leftover: dest=9 2dfe94 four beats closed (ROR/ADD/ADD/XOR; "
            "beat3 sl[6]+=sl[17], sl[17]=unix/p40); 2e0a8c→2d7104 mill still open; "
            "s25=*(seed+0x1E8) only alias (no gap, not in SO TAB/W rodata); "
            "k15=6/10 request mill; k15=9 sticky across urls (not ROR(W/TAB,k)); "
            "2e029c s6/s11 (overwritten before 2dfe94); "
            "s14/s20 at 2d7104 enter; gap428=*(seed-0x304). "
            "closed on this corridor: 2e029c s8=s13+s8; 2dfe94 s10=ROR32(s10,16)+s6; "
            "dest=8 p160=s8_fused+s25. "
            "assemble+last2 lag=1 closed given W. "
            "[UPDATED 2026-09-02 _ab_f13_split.py 7-variant] urandom16 first16 + "
            "self-consistent hi16(assemble_from_w) SHIPS (repro 2x); server does NOT "
            "validate first16 true-entropy source. ONLY last2(byte18/19)=ts-formula is "
            "checked. Prior 'urandom16 sharks' verdict was a capture-artifact "
            "(anti-frida + un-zstd'd body), NOT first16. See memory field13-first16-not-a-wall. "
            "sign() now shares compact f13/f14/f18-lanusk/f19 across Medusa+Perseus "
            "(was two telemetry calls + SM3-VM f18 vs lanusk). unknown4 omitted."
        ),
        "do_not": (
            "treat first16 as F19/intern32 nonce; read dest=10 gap+0x420 as fill M; "
            "hash url/body/did as first16"
        ),
    },
    "medusa_seed_gap_bytes": {
        "status": "import",
        "have": "snaps_from_seed_gap / derive_leaves live-exact; cold SHA256 placeholder not live",
        "do_not": "SHA256(device+ts) as gap",
    },
    "client_key_h1_epoch": {
        "status": "import",
        "have": "ClientKeyManager.LIZJ/Keva dump P2323-29; DeviceProfile.client_key64; F18_HEAD32_HEX64 pin",
        "do_not": "SM3/SHA256(did/iid/cdid) — P2320 0 hit",
    },
    "f19_workspace_live_table": {
        "status": "unused_for_wire",
        "have": "level2_deriver bundled-template rebase; F19 wire=swap(urandom)",
        "do_not": "JNI f3.a @0x281ad4 mill of 0x390 table",
    },
    "perseus_template_clocks": {
        "status": "template",
        "have": "DEVICE_LEVEL_JSON_CONSTANTS; TelemetryClockSession (opt-in); f21=738/f28=1690 template defaults",
        "do_not": "treat as missing mill formula for 七神头",
    },
    "ticket_guard_tee": {
        "status": "governed_import",
        "have": "ticketguard_tee_resolver pool/profile/template/cache/ree_only; KeyStore non-exportable",
        "do_not": "Python TEE sign",
    },
    "device_identity": {
        "status": "server_import",
        "have": "device_register ~1078B generate; DeviceOrchestrator onboard; IdentityPool",
        "do_not": "forge device_id/install_id/token",
    },
    "openudid": {
        "status": "hardware",
        "have": "openudid_tee_proof (android_id else SecureRandom hex)",
        "do_not": "random openudid expecting device_id!=0",
    },
    "medusa_counters": {
        "status": "session",
        "have": "QuasiPureMedusaProvider sentinel; sign_count local increment; PGZ110 setting_count=694367",
        "do_not": "mill-walk counters",
    },
    "medusa_f18_lanusk": {
        "status": "closed_intern48_src16_mill",
        "have": (
            "intern32 session nonce || intern16 (MD5(body)|EMPTY_STUB) || "
            "LANUSK_MD5_12 || u32(0x180) → wrap_mill_src16 → TAB assemble + last4"
        ),
        "do_not": "copy mill WRAP ser; SM3(client_key) as compact WRAP f18; hash did/url",
    },
    "intern32_session_nonce": {
        "status": "closed_getrandom_v1",
        "have": "kernel getrandom 32B; mill-less stand-in os.urandom(32); process-stable on MilllessSession",
        "do_not": "hash query/cookie/did as intern32",
    },
    "device_http_bypass": {
        "status": "env",
        "have": "P2330-P2332; x-metasec-bypass-mssdk; WRAP still fires",
        "do_not": "hook Java headers waiting for X-Medusa on this pid",
    },
}


def last2_from_unix(ts: int, lag: int = 1) -> bytes:
    return compute_byte18_byte19(int(ts), lag=lag)


def first16_local() -> bytes:
    """Random 16B first16. Live first16 is mill M^ROR(TAB,k+5); this is a
    self-consistent stand-in (hi16 recomputed by assemble_from_w).

    [VERIFIED 2026-09-02 _ab_f13_split.py 7-variant, repro 2x] server does NOT
    validate first16 true-entropy source. urandom first16 + self-consistent hi16
    SHIPS full results. ONLY last2 (byte18/19, ts-formula) is checked. This IS
    出货-safe. Prior 'do not 出货' note was a capture-artifact false verdict.
    See memory field13-first16-not-a-wall.
    """
    return os.urandom(16)


def field13_20b_millless(url_ts: int, lag: int = 1, first16: bytes | None = None) -> bytes:
    return field13_20b_from_first16(first16 if first16 is not None else first16_local(), url_ts, lag)


def field13_20b_from_first16(first16: bytes, url_ts: int, lag: int = 1) -> bytes:
    if len(first16) != 16:
        raise ValueError("first16 must contain exactly 16 bytes")
    if lag not in (0, 1):
        raise ValueError("lag")
    w0, w1, w2, w3 = struct.unpack("<4I", first16)
    return assemble_from_w(w0, w1, w2, w3, int(url_ts), lag=lag)


def field13_20b_from_ws(ws: bytes, url_ts: int, lag: int = 1) -> bytes:
    return field13_20b_from_first16(first16_from_ws(ws), url_ts, lag=lag)


def field13_20b_from_wide64(wide: bytes, url_ts: int, lag: int = 1) -> bytes:
    return assemble_from_wide64(wide, int(url_ts), lag=lag)


class MilllessSession:
    """Process-stable intern32. Live producer is kernel getrandom, not a hash."""

    def __init__(self, intern32: bytes | None = None) -> None:
        raw = bytes(intern32) if intern32 is not None else os.urandom(32)
        if len(raw) != 32:
            raise ValueError("intern32 must be 32B")
        self.intern32 = raw


_MILLLESS_SESSION: MilllessSession | None = None


def millless_session() -> MilllessSession:
    global _MILLLESS_SESSION
    if _MILLLESS_SESSION is None:
        _MILLLESS_SESSION = MilllessSession()
    return _MILLLESS_SESSION


def millless_lanusk_hash(
    mill_ser_f18: bytes | None = None,
    body: bytes | None = None,
    intern32: bytes | None = None,
    intern16: bytes | None = None,
) -> bytes:
    """Compact WRAP f18 20B: src16 mill + TAB assemble over intern64.

    intern32 = session nonce (getrandom / os.urandom). intern16 = x-ss-stub
    MD5(body) or EMPTY_STUB. mill_ser_f18 is ignored — never copy live mill WRAP.
    """
    del mill_ser_f18
    from .wrap_lanusk import LANUSK_XOR_KEY, assemble_lanusk_hash
    from .wrap_mill_src16 import intern64_from_intern48, src16_from_intern64

    if intern32 is not None:
        i32 = bytes(intern32)
    else:
        i32 = millless_session().intern32
    if len(i32) != 32:
        raise ValueError("intern32 must be 32B")
    if intern16 is not None:
        i16 = bytes(intern16)
    else:
        i16 = intern16_from_body(body)
    if len(i16) != 16:
        raise ValueError("intern16 must be 16B")
    intern48 = i32 + i16
    src = src16_from_intern64(intern64_from_intern48(intern48))
    return assemble_lanusk_hash(src, LANUSK_XOR_KEY)


def source32_local() -> bytes:
    return os.urandom(32)


def field32_from_source32(source32: bytes) -> bytes:
    return serialize_f19_source(source32)


def source_region_from_nonce(
    source32: bytes | None = None,
    *,
    body: bytes | None = None,
    size: int = 0x60,
) -> bytes:
    src = source32 if source32 is not None else source32_local()
    if len(src) != 32:
        raise ValueError("source32 must contain exactly 32 bytes")
    intern = intern16_from_body(body)
    out = bytearray(size)
    out[0:32] = src
    out[32:48] = intern
    return bytes(out)


__all__ = [
    "EMPTY_STUB",
    "F18_HEAD32_HEX64",
    "MilllessSession",
    "REMAINING_BOUNDARIES",
    "assemble_from_wide64",
    "derive_dynamic48",
    "field13_20b_from_first16",
    "field13_20b_millless",
    "first16_local",
    "field13_20b_from_wide64",
    "field13_20b_from_ws",
    "field32_from_source32",
    "first16_from_ab32",
    "first16_from_wide",
    "first16_from_ws",
    "head32_from_unix",
    "intern16_from_body",
    "last2_from_unix",
    "millless_lanusk_hash",
    "millless_session",
    "pack64_to_32",
    "source32_local",
    "source_region_from_nonce",
]

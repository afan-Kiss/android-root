"""Seed/gap leaf formulas for Medusa xor34-20B (P1857–P2055).

Assemble itself is already closed given snaps. This module closes the
ABS leaves that used to live in ``LEAF_BOARD.ABS_OPEN``:

  p148 = *(gap+524) + ((u8(gap+himm)<<24)|s10)     (p148_cold)
  s10  = ((u8(gap+ld)<<8)|u8(gap+lo))|(u8(gap+dd)<<16)
  p158 = (ROR32(0x3DF5A9A5, k) + *(seed+0x1F8))     (p158_cold)
  slot[23] = *(seed+0x1D8)
  p150/p160/p168 at serialize = *(seed+0x150/0x160/0x168)

TAB/tbl are SO constants (``+0xC3040``, ``*(+0xEA900+0x3C)``).
s5_old on the xor34-f13 path is 416.

Gap/seed *contents* are session material (governed import), not SHA256.
"""
from __future__ import annotations

import struct
from typing import Any, Mapping

from .medusa_field13_assemble import (
    C_PRE,
    C_S9,
    C_S10,
    S5_PRIOR_FINAL,
    TAB_OFF,
    k_from_ts,
    rol32,
    ror32,
)

GAP_FROM_SEED = 0x4B0
SEED_P148 = 0x148
SEED_P150 = 0x150
SEED_P158 = 0x158
SEED_P160 = 0x160
SEED_P168 = 0x168
SEED_SLOT23 = 0x1D8
SEED_S27 = 0x1F8
TBL_OFF = 0xEA900 + 0x3C
W_OFF = 0xEA9C0
EA900_TAB_OFF = 0xEA900  # tbl at +0x3C; p158@1A84 const at +0
P158_1A84_OFF = EA900_TAB_OFF
C516 = 0x3DF5A9A5
C84_MILL = 0xF8209B26  # 1A84 m84 = ROR32(C84, k) (P2058 5/5)
C88_MILL = 0xD785F19B
C8C_MILL = 0x916A4AE1
GAP_SPRAY_BASE = 480  # gap[480+4*i]=ROR32(W[i],s6) for i=0..11 (P2057 live 3/3)
GAP_SPRAY_WORDS = 12
C_S26 = 0x9BE0826C  # P1693 sticky s26
LO_TO_LD = {18: 90, 33: 165}  # ld=5*lo (P1693)

# Observed live k → gap imm (P1861/P1862). k=10/26 share a family; k=9/25 share.
P148_IMM_BY_K: dict[int, dict[str, int]] = {
    22: {"ld": 292, "lo": 332, "dd": 316, "himm": 420},
    6: {"ld": 292, "lo": 332, "dd": 316, "himm": 420},
    10: {"ld": 300, "lo": 332, "dd": 320, "himm": 420},
    26: {"ld": 300, "lo": 332, "dd": 320, "himm": 420},
    9: {"ld": 300, "lo": 340, "dd": 336, "himm": 428},
    25: {"ld": 300, "lo": 340, "dd": 336, "himm": 428},
}
P148_IMM_BY_K15: dict[int, dict[str, int]] = {
    6: P148_IMM_BY_K[6],
    9: P148_IMM_BY_K[9],
    10: P148_IMM_BY_K[10],
}
# k15=9 p148 u8s are SO/session-stable (P1861 + P2058 live 2/2).
P148_U8_K15_9 = {"ld": 168, "lo": 166, "dd": 88, "himm": 199}
P148_DD_MILLPAIR = 221  # 0xDD for k15 in {6,10}


def u32le_at(buf: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(buf):
        raise ValueError(f"u32 read out of range: off={off:#x} len={len(buf)}")
    return struct.unpack_from("<I", buf, off)[0]


def i32le_at(buf: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(buf):
        raise ValueError(f"i32 read out of range: off={off:#x} len={len(buf)}")
    return struct.unpack_from("<i", buf, off)[0] & 0xFFFFFFFF


def u8_at(buf: bytes, off: int) -> int:
    if off < 0 or off >= len(buf):
        raise ValueError(f"u8 read out of range: off={off:#x} len={len(buf)}")
    return buf[off]


def p148_imm_for_k(k: int) -> dict[str, int]:
    if k in P148_IMM_BY_K:
        return P148_IMM_BY_K[k]
    family = P148_IMM_BY_K15.get(k & 15)
    if family is not None:
        return family
    raise KeyError(f"no p148 imm table for k={k} (k&15={k & 15})")


def s10_from_gap(gap: bytes, k: int) -> int:
    """P1859/P1861: s10=((u8(ld)<<8)|u8(lo))|(u8(dd)<<16); gap=seed-0x4B0."""
    imm = p148_imm_for_k(k)
    ld = u8_at(gap, imm["ld"])
    lo = u8_at(gap, imm["lo"])
    dd = u8_at(gap, imm["dd"])
    return (((ld << 8) | lo) | (dd << 16)) & 0xFFFFFFFF


def s21_from_gap_s10(gap: bytes, k: int, s10: int | None = None) -> int:
    """P1282/P1861: s21=(u8(himm)<<24)|s10."""
    imm = p148_imm_for_k(k)
    if s10 is None:
        s10 = s10_from_gap(gap, k)
    hi = (u8_at(gap, imm["himm"]) << 24) & 0xFFFFFFFF
    return (hi | (s10 & 0xFFFFFFFF)) & 0xFFFFFFFF


def p148_from_gap(gap: bytes, k: int) -> int:
    """P1857/P1858: p148 = *(gap+524) + s21."""
    plant = i32le_at(gap, 524)
    return (plant + s21_from_gap_s10(gap, k)) & 0xFFFFFFFF


def plant_p148_u8s(gap: bytearray, k: int) -> None:
    """Write p148 ld/lo/dd/himm bytes at k-imm offsets (P2058)."""
    imm = p148_imm_for_k(k)
    u8s = p148_u8_from_k(k)
    for key in ("ld", "lo", "dd", "himm"):
        gap[imm[key]] = u8s[key] & 0xFF


def p148_from_k_so(so: bytes, k: int) -> int:
    """P2058: p148 from SO+k only (k∈{6,9,10,22,25,26} live P2058/P2059).

    Plants ROR32(W[11], k+3) at gap[524] and the closed p148 u8s at k-imm
    offsets. Does not require a live gap dump.
    """
    gap = bytearray(600)
    block = gap_spray_block_from_so_k(so, k)
    gap[GAP_SPRAY_BASE : GAP_SPRAY_BASE + len(block)] = block
    plant_p148_u8s(gap, k)
    return p148_from_gap(bytes(gap), k)


def p158_from_seed(seed: bytes, k: int) -> int:
    """P1910: p158 = (ROR32(0x3DF5A9A5, k) + *(seed+0x1F8)) >>> 0."""
    s27 = u32le_at(seed, SEED_S27)
    return (ror32(C516, k) + s27) & 0xFFFFFFFF


def p158_at_1a84_from_so(so: bytes, k: int) -> int:
    """P2058: *(seed+0x158) at H_1A84 = ROR32(*(SO+0xEA900), k) (mixed 5/5).

    This is mill-time p158, not serialize-time p158_cold (P1910 still needs s27).
    """
    return ror32(u32le_at(so, P158_1A84_OFF), k)


def mill_m84_from_k(k: int) -> int:
    """P2058: 1A84 m84 = ROR32(0xf8209b26, k) (5/5)."""
    return ror32(C84_MILL, k)


def mill_m88_from_k(k: int) -> int:
    """STR1/P2058: 1A84 m88 = ROR32(0xd785f19b, k)."""
    return ror32(C88_MILL, k)


def mill_m8c_from_k(k: int) -> int:
    """STR1/P2058: 1A84 m8c = ROR32(0x916a4ae1, k)."""
    return ror32(C8C_MILL, k)


def slot23_from_seed(seed: bytes) -> int:
    """slot[23] / s23 = *(seed+0x1D8)."""
    return u32le_at(seed, SEED_SLOT23)


def load_tab_from_so(so: bytes) -> list[int]:
    if len(so) < TAB_OFF + 16:
        raise ValueError(f"SO too small for TAB at {TAB_OFF:#x}")
    return [u32le_at(so, TAB_OFF + i * 4) for i in range(4)]


def load_tbl_from_so(so: bytes) -> int:
    if len(so) < TBL_OFF + 4:
        raise ValueError(f"SO too small for tbl at {TBL_OFF:#x}")
    return u32le_at(so, TBL_OFF)


def load_w_from_so(so: bytes, n: int = 20) -> list[int]:
    """P1690: spray table T[0..n) at libmetasec_ml.so+0xea9c0."""
    if len(so) < W_OFF + n * 4:
        raise ValueError(f"SO too small for W[{n}] at {W_OFF:#x}")
    return [u32le_at(so, W_OFF + i * 4) for i in range(n)]


def lo_from_ts(ts: int) -> int:
    """P1693: lo = 18 if ((ts>>3)&1) else 33 (81/81). ts is query ts= seconds."""
    return 18 if (int(ts) >> 3) & 1 else 33


def b_from_ts(ts: int) -> int:
    """P1692: epoch bit b = (ts>>4)&1 (81/81)."""
    return (int(ts) >> 4) & 1


def spray_s6(lo: int, b: int) -> int:
    """P1691: spray s6 = 9+4*(lo==18)+16*b (AH=8). lo∈{18,33}, b∈{0,1}."""
    return (9 + (4 if (lo & 0xFF) == 18 else 0) + 16 * (b & 1)) & 31


def spray_s6_from_k(k: int) -> int:
    """P2058 live mixed k∈{6,9,10,26}: spray rotate s6=(k+3)&31."""
    return (int(k) + 3) & 31


def spray_s6_from_ts(ts: int) -> int:
    """P1693: s6 = 9+4*((ts>>3)&1)+16*((ts>>4)&1). Agrees with k+3 on mill-pair k."""
    return spray_s6(lo_from_ts(ts), b_from_ts(ts))


def mill_pair_lo_from_k(k: int) -> int:
    """P2058: k15=10 → lo=18, k15=6 → lo=33. k15=9 uses a different mill-pair."""
    k15 = int(k) & 15
    if k15 == 10:
        return 18
    if k15 == 6:
        return 33
    raise KeyError(f"no mill-pair lo for k={k} (k&15={k15})")


def p148_u8_from_k(k: int) -> dict[str, int]:
    """p148 ld/lo/dd/himm bytes.

    k15∈{6,10}: mill-pair lo from k, ld=5*lo, dd=0xDD, himm=136-lo (P2058).
    k15=9: constants 168/166/88/199 (P1861 + P2058 2/2).
    """
    k15 = int(k) & 15
    if k15 == 9:
        return dict(P148_U8_K15_9)
    lo = mill_pair_lo_from_k(k)
    return {"ld": 5 * lo, "lo": lo, "dd": P148_DD_MILLPAIR, "himm": (136 - lo) & 0xFF}


def s21_from_k(k: int) -> int:
    """dest=16/dest=10 s21 = u32le(lo, ld, dd, himm) from p148_u8_from_k.

    Live dest=10 sl[21] 18/18 on k∈{6,9,10,22,25,26}. Low 24 bits = dest=6 s10
    ((dd<<16)|(ld<<8)|lo). High byte = himm.
    """
    u = p148_u8_from_k(k)
    return (
        (u["lo"] & 0xFF)
        | ((u["ld"] & 0xFF) << 8)
        | ((u["dd"] & 0xFF) << 16)
        | ((u["himm"] & 0xFF) << 24)
    ) & 0xFFFFFFFF


def s10_d6_from_k(k: int) -> int:
    """dest=6 s10 = s21_from_k low 24 bits (P1293 pack)."""
    return s21_from_k(k) & 0x00FFFFFF


def mill_pair_ld(lo: int) -> int:
    """P1693: ld = 5*lo (90 when lo=18, 165 when lo=33)."""
    lo &= 0xFF
    if lo not in LO_TO_LD:
        raise KeyError(f"no mill-pair ld for lo={lo}")
    return 5 * lo


def s26_sticky_from_ts(ts: int) -> int:
    """P1693: s26 = ROL32(0x9be0826c, (16*b-4*((ts>>3)&1))&31) (21/21)."""
    b = b_from_ts(ts)
    lo_bit = (int(ts) >> 3) & 1
    return rol32(C_S26, (16 * b - 4 * lo_bit) & 31)


def gap_spray_u32(w: list[int], w_index: int, s6: int) -> int:
    """gap[480+4*w_index] = ROR32(W[w_index], s6) (P1690/P2057 live 3/3)."""
    if w_index < 0 or w_index >= len(w):
        raise KeyError(f"W index {w_index} out of range")
    return ror32(w[w_index], s6)


def gap_spray_block(w: list[int], s6: int, n: int = GAP_SPRAY_WORDS) -> bytes:
    """48-byte little-endian block for gap[480:528]."""
    return b"".join(struct.pack("<I", gap_spray_u32(w, i, s6)) for i in range(n))


def gap508_from_w(w: list[int], s6: int) -> int:
    """P1690: gap[508] = ROR32(W[7], s6)."""
    return gap_spray_u32(w, 7, s6)


def gap524_from_w(w: list[int], s6: int) -> int:
    """P2057: gap[524] = ROR32(W[11], s6). Live 3/3 + historical 5/5."""
    return gap_spray_u32(w, 11, s6)


def gap_spray_block_from_so_k(so: bytes, k: int) -> bytes:
    """Pure SO+k spray block for gap[480:528] (P2058 s6=k+3)."""
    return gap_spray_block(load_w_from_so(so, GAP_SPRAY_WORDS), spray_s6_from_k(k))


def gap_spray_block_from_so_ts(so: bytes, ts: int) -> bytes:
    """Pure SO+ts spray block for gap[480:528] (P1693)."""
    return gap_spray_block(load_w_from_so(so, GAP_SPRAY_WORDS), spray_s6_from_ts(ts))


def s27_from_k_table(k: int, *, m60: int, m64: int) -> int:
    """P2024: s25@1A84 = *(seed-0x60) when k15==6 else *(seed-0x64); s27=s25."""
    k15 = k & 15
    if k15 == 6:
        return m60 & 0xFFFFFFFF
    if k15 in (9, 10):
        return m64 & 0xFFFFFFFF
    raise KeyError(f"no s27 k-table alias for k={k} (k&15={k15})")


def s3_from_k_table(k: int, *, m70: int, m7c: int, p40: int) -> int:
    """P2024: s3@1A84 = m70 (k15=6), m7c (k15=10), p40 (k15=9)."""
    k15 = k & 15
    if k15 == 6:
        return m70 & 0xFFFFFFFF
    if k15 == 10:
        return m7c & 0xFFFFFFFF
    if k15 == 9:
        return p40 & 0xFFFFFFFF
    raise KeyError(f"no s3 k-table alias for k={k} (k&15={k15})")


# Fill-window seed-neg (P2062): PRE 2e4a6c / hid=310 64B buffer.
# gap = seed - 0x4B0, so seed-X lives at gap+(0x4B0-X).
FILL_H0_GAP_OFF = 0x4B0 - 0x140  # 0x370
FILL_M90_GAP_OFF = 0x4B0 - 0x90  # 0x420
# P2078: after andHits move, dest=10 m90 at 0x420 is already fill M, but
# ROR(C_S9,k+5)/ROR(C_PRE,k+5) still sit at gap+0x1d8/0x1dc (mill-wrap + dest=10).
STICKY_C9_GAP_OFF = 0x1D8
STICKY_PRE_GAP_OFF = 0x1DC


def ror_tab_k5(tab: list[int], k: int) -> list[int]:
    """P2062 3/3 (k=9): andHits h[i] = ROR32(TAB[i], (k+5)&31) = *(seed-0x140+4*i)."""
    amt = (int(k) + 5) & 31
    return [ror32(int(t), amt) for t in tab[:4]]


def fill_h_from_gap(gap: bytes) -> list[int]:
    """andHits h0..h3 at seed-0x140..-0x134 (P2062 3/3)."""
    return [u32le_at(gap, FILL_H0_GAP_OFF + 4 * i) for i in range(4)]


def fill_slots_hold_ser_w(seed: bytes, gap: bytes) -> bool:
    """P2079: SER-epoch mill-wrap copies W into seed; fill slots already hold W.

    PRE-308090 fill M is only in gap+0x420 and is not the proto first16 in seed.
    """
    if not seed or len(gap) < FILL_M90_GAP_OFF + 16:
        return False
    raw = struct.pack("<IIII", *fill_m_from_gap(gap))
    return raw in seed


def fill_m_from_gap(gap: bytes) -> tuple[int, int, int, int]:
    """Fill staging (m90, m8c, m88, m84) at seed-0x90..-0x84 (P2062 3/3).

    Epoch is PRE ``bl 0x308090`` (SO+0x2e4a6c). After that helper, seed-0x88
    is overwritten with W2. m8c equals hid=310 STR val (slot[5] after hid=262).
    """
    return (
        u32le_at(gap, FILL_M90_GAP_OFF),
        u32le_at(gap, FILL_M90_GAP_OFF + 4),
        u32le_at(gap, FILL_M90_GAP_OFF + 8),
        u32le_at(gap, FILL_M90_GAP_OFF + 12),
    )


def w_from_fill_gap(gap: bytes, k: int, tab: list[int]) -> tuple[int, int, int, int]:
    """Live first16: W[i] = M[i] ^ ROR32(TAB[i], k+5) (P2062 3/3)."""
    m90, m8c, m88, m84 = fill_m_from_gap(gap)
    h = ror_tab_k5(tab, k)
    gap_h = fill_h_from_gap(gap)
    if gap_h != h:
        raise ValueError(f"fill andHits {gap_h} != ROR(TAB,k+5) {h} (k={k})")
    return (
        (m90 ^ h[0]) & 0xFFFFFFFF,
        (m8c ^ h[1]) & 0xFFFFFFFF,
        (m88 ^ h[2]) & 0xFFFFFFFF,
        (m84 ^ h[3]) & 0xFFFFFFFF,
    )


def fill_gap_ready(gap: bytes, k: int, tab: list[int]) -> bool:
    """True when mill gap is PRE-308090 fill epoch (andHits == ROR(TAB, k+5))."""
    if len(gap) < FILL_M90_GAP_OFF + 16:
        return False
    try:
        return fill_h_from_gap(gap) == ror_tab_k5(tab, k)
    except ValueError:
        return False


def mill_m90_gate_from_k(k: int) -> int:
    """P2063: dest=10 seed-0x90 = ROR32(C_PRE, k+5). Equals fill m90 before idx=6 ADD."""
    return ror32(C_PRE, (int(k) + 5) & 31)


def mill_m84_gate_from_k(k: int) -> int:
    """P2063: dest=10 m84 = ROR32(C_S10, k+5) = ROR32(C84, k)."""
    return ror32(C_S10, (int(k) + 5) & 31)


def mill_m88_gate_from_k(k: int) -> int:
    """P2063: dest=10 m88 = ROR32(C_S9, k+5) = ROR32(C88, k)."""
    return ror32(C_S9, (int(k) + 5) & 31)


def fill_m_from_idx69(
    *,
    k: int,
    p160_idx6: int,
    p150_idx6: int,
    p168_idx9: int,
    p148_idx9: int,
    p158_idx9: int,
) -> tuple[int, int, int, int]:
    """P2063/P2064: fill M from 3017d8 idx=6/9 + hid=262 p158.

    Live assemble==20B on k∈{9,10,22,25}. 0x301730 does LDRSW then ADD then ORR:
    idx=6 p150 = sl6 + sl8 after LDRSW *(gap+452)→sl10;
    idx=9 p168 = sl7 + ROR32(C8C,k) after LDRSW *(gap+468)→sl9, and *(gap+468)=ROR32(C8C,k).
    dest=10 slots are rewritten by a static mill stream before 301730 (P2065).
    """
    amt = (int(k) + 5) & 31
    m90 = (ror32(C_PRE, amt) + (p160_idx6 & 0xFFFFFFFF)) & 0xFFFFFFFF
    m84 = (ror32(C_S10, amt) + (p150_idx6 & 0xFFFFFFFF)) & 0xFFFFFFFF
    m88 = (
        (p168_idx9 & 0xFFFFFFFF)
        + ror32(C_S9, amt)
        - mill_m8c_from_k(k)
    ) & 0xFFFFFFFF
    eor = ((p150_idx6 & 0xFFFFFFFF) ^ (p158_idx9 & 0xFFFFFFFF)) & 0xFFFFFFFF
    m8c = (
        (p168_idx9 & 0xFFFFFFFF)
        + ror32((p148_idx9 + eor) & 0xFFFFFFFF, 11)
    ) & 0xFFFFFFFF
    return m90, m8c, m88, m84


def fill_m_from_d10_seed_gap(seed: bytes, gap: bytes, k: int) -> tuple[int, int, int, int]:
    """P2065: dest=10 seed+gap mill-walk to idx=6/9 then fill_m_from_idx69."""
    from .medusa_field13_mill_d10 import mill_walk_d10_to_idx69

    walked = mill_walk_d10_to_idx69(seed, gap, k)
    return fill_m_from_idx69(
        k=k,
        p160_idx6=walked["p160_idx6"],
        p150_idx6=walked["p150_idx6"],
        p168_idx9=walked["p168_idx9"],
        p148_idx9=walked["p148_idx9"],
        p158_idx9=walked["p158_idx9"],
    )


def mill_d10_ready(gap: bytes, k: int) -> bool:
    """True when mill gap is dest=10 k-gate epoch (m90 == ROR(C_PRE, k+5))."""
    from .medusa_field13_mill_d10 import mill_d10_ready as _ready

    return _ready(gap, k)


def k_from_mill_d10_gap(gap: bytes) -> int | None:
    """P2068: dest=10 k uniquely inverted from m90/m84/m88 gates. No tbl/ts."""
    if len(gap) < FILL_M90_GAP_OFF + 16:
        return None
    m90, _, m88, m84 = fill_m_from_gap(gap)
    hits = [
        k
        for k in range(32)
        if mill_m90_gate_from_k(k) == m90
        and mill_m84_gate_from_k(k) == m84
        and mill_m88_gate_from_k(k) == m88
    ]
    return hits[0] if len(hits) == 1 else None


def k_from_fill_gap(gap: bytes, tab: list[int]) -> int | None:
    """P2068: fill-epoch k uniquely inverted from andHits == ROR(TAB, k+5)."""
    if len(gap) < FILL_H0_GAP_OFF + 16:
        return None
    h = fill_h_from_gap(gap)
    hits = [k for k in range(32) if ror_tab_k5(tab, k) == h]
    return hits[0] if len(hits) == 1 else None


def k_from_sticky_gap(gap: bytes) -> int | None:
    """P2078: k from sticky C_S9/C_PRE copies after fill H and dest=10 m90 have moved."""
    from .medusa_field13_assemble import C_PRE, C_S9

    if len(gap) < STICKY_PRE_GAP_OFF + 4:
        return None
    c9 = u32le_at(gap, STICKY_C9_GAP_OFF)
    pre = u32le_at(gap, STICKY_PRE_GAP_OFF)
    hits = [
        k
        for k in range(32)
        if ror32(C_S9, (k + 5) & 31) == c9 and ror32(C_PRE, (k + 5) & 31) == pre
    ]
    return hits[0] if len(hits) == 1 else None


def snaps_from_seed_gap(
    seed: bytes,
    gap: bytes,
    *,
    k: int,
) -> dict[str, int]:
    """Derive compose snaps from serialize-time seed + mill gap.

    p148/p158 use the closed mill formulas. p150/p160/p168/p148_m8c are the
    serialize-time seed words (P1948/P1946/P1865). p148_pres8 uses p148_cold
    when gap is present (NEXTPC s5), which is the leaf that used to be ABS_OPEN.
    """
    if len(seed) < SEED_S27 + 4:
        raise ValueError(f"seed must cover +0x1F8, got {len(seed)} bytes")
    if len(gap) < 528:
        raise ValueError(f"gap must cover +524, got {len(gap)} bytes")
    p148 = p148_from_gap(gap, k)
    p158 = p158_from_seed(seed, k)
    p150 = u32le_at(seed, SEED_P150)
    p160 = u32le_at(seed, SEED_P160)
    p168 = u32le_at(seed, SEED_P168)
    p148_m8c = u32le_at(seed, SEED_P148)
    return {
        "k": k & 0xFFFFFFFF,
        "p148_pres8": p148,
        "p160_pres8": p160,
        "p150": p150,
        "p158": p158,
        "p148_m8c": p148_m8c,
        "p168_m8c": p168,
        "s23": slot23_from_seed(seed),
        "s5_old": S5_PRIOR_FINAL,
        "s10": s10_from_gap(gap, k),
        "s21": s21_from_gap_s10(gap, k),
        "s27": u32le_at(seed, SEED_S27),
    }


def _as_bytes(value: Any, name: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("hex:"):
            text = text[4:]
        return bytes.fromhex(text)
    raise TypeError(f"{name} must be bytes or hex string")


def maybe_snaps_from_material(material: Mapping[str, Any], *, k: int) -> dict[str, int] | None:
    """If closure carries seed+gap, derive snaps; else None."""
    seed_raw = material.get("seed") or material.get("medusa_seed")
    gap_raw = material.get("gap") or material.get("medusa_gap")
    if seed_raw is None or gap_raw is None:
        return None
    return snaps_from_seed_gap(_as_bytes(seed_raw, "seed"), _as_bytes(gap_raw, "gap"), k=k)


__all__ = [
    "C516",
    "C84_MILL",
    "C88_MILL",
    "C8C_MILL",
    "GAP_FROM_SEED",
    "P148_IMM_BY_K",
    "P158_1A84_OFF",
    "SEED_S27",
    "SEED_SLOT23",
    "TBL_OFF",
    "C_S26",
    "GAP_SPRAY_BASE",
    "LO_TO_LD",
    "W_OFF",
    "b_from_ts",
    "gap508_from_w",
    "gap524_from_w",
    "gap_spray_block",
    "gap_spray_block_from_so_k",
    "gap_spray_block_from_so_ts",
    "gap_spray_u32",
    "load_tab_from_so",
    "load_tbl_from_so",
    "load_w_from_so",
    "lo_from_ts",
    "maybe_snaps_from_material",
    "mill_m84_from_k",
    "mill_m88_from_k",
    "mill_m8c_from_k",
    "mill_pair_ld",
    "mill_pair_lo_from_k",
    "p148_from_gap",
    "p148_from_k_so",
    "p148_imm_for_k",
    "p148_u8_from_k",
    "p158_at_1a84_from_so",
    "p158_from_seed",
    "plant_p148_u8s",
    "s10_from_gap",
    "s21_from_gap_s10",
    "s21_from_k",
    "s10_d6_from_k",
    "s26_sticky_from_ts",
    "s27_from_k_table",
    "s3_from_k_table",
    "slot23_from_seed",
    "snaps_from_seed_gap",
    "FILL_H0_GAP_OFF",
    "FILL_M90_GAP_OFF",
    "fill_h_from_gap",
    "fill_m_from_gap",
    "fill_slots_hold_ser_w",
    "fill_gap_ready",
    "fill_m_from_idx69",
    "fill_m_from_d10_seed_gap",
    "mill_d10_ready",
    "k_from_mill_d10_gap",
    "k_from_fill_gap",
    "k_from_sticky_gap",
    "mill_m90_gate_from_k",
    "mill_m84_gate_from_k",
    "mill_m88_gate_from_k",
    "ror_tab_k5",
    "w_from_fill_gap",
    "spray_s6",
    "spray_s6_from_k",
    "spray_s6_from_ts",
    "u32le_at",
]

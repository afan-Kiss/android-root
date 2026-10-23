# -*- coding: utf-8 -*-
"""Static mill bytecode dest=9 ADD through 301730 idx=6 to idx=9 enter (P2065/P2066).

Fused simple-op stream is identical across live k∈{6,9,10,22,25,26}. Compound packing
differs: k15∈{9,25} uses 0x2e0a8c/0x2dda90; k15∈{6,10} uses 0x2d4150/0x2d7104/
0x2da29c (LDRSW then ADD, skip +3). Do not hook BR 0x2d810c or 0x301730.
"""
from __future__ import annotations

from .medusa_field13_assemble import C_PRE, ror32

SEED_SLOT0 = 0x120
N_SLOTS = 32
FILL_M90_GAP_OFF = 0x420
# seed-0x60/64/70/7c live in dest=10 gap; mill-walk LDRSW never reads these (P2072).
K_TABLE_GAP_OFF = {
    "m60": 0x4B0 - 0x60,  # 0x450
    "m64": 0x4B0 - 0x64,  # 0x44C
    "m70": 0x4B0 - 0x70,  # 0x440
    "m7c": 0x4B0 - 0x7C,  # 0x434
}
C8C_MILL = 0x916A4AE1
D10_ADD_A, D10_ADD_B, D10_ADD_D = 9, 15, 9
IDX6_LDRSW = ("2d02a8", 4, 10, 452)

MILL_D10_TO_IDX9_OPS = (
    ('2cf838', 10, 0, 15, 15),
    ('2cf70c', 10, 20, 10, 10),
    ('2d0c54', 9, 9, 26, 26),
    ('2cf70c', 10, 14, 10, 10),
    ('2cf70c', 9, 8, 9, 9),
    ('2ced6c', 9, 15, 14, 14),
    ('2d21d4', 14, 8, 8, 8),
    ('2cf70c', 6, 8, 6, 6),
    ('2d0c54', 6, 6, 22, 22),
    ('2cf70c', 6, 9, 6, 6),
    ('2ced6c', 6, 11, 8, 8),
    ('2cf838', 9, 0, 11, 11),
    ('2d21d4', 8, 9, 8, 8),
    ('2cf70c', 13, 9, 9, 9),
    ('2d02a8', 4, 13, 172, 428),
    ('2cf70c', 10, 8, 8, 8),
    ('2d0c54', 8, 8, 17, 17),
    ('2cf70c', 8, 6, 8, 8),
    ('2ced6c', 8, 11, 10, 10),
    ('2cf838', 6, 0, 11, 11),
    ('2d21d4', 10, 6, 10, 10),
    ('2cf70c', 13, 6, 6, 6),
    ('2d02a8', 4, 13, 176, 432),
    ('2cf70c', 12, 10, 10, 10),
    ('2cf838', 8, 0, 12, 12),
    ('2d0c54', 10, 10, 11, 11),
    ('2cf70c', 10, 8, 10, 10),
    ('2ced6c', 10, 11, 11, 11),
    ('2d21d4', 11, 8, 11, 11),
    ('2cf70c', 25, 8, 8, 8),
    ('2cf70c', 9, 11, 9, 9),
    ('2d0c54', 9, 9, 26, 26),
    ('2cf70c', 9, 10, 9, 9),
    ('2ced6c', 9, 12, 11, 11),
    ('2cf838', 10, 0, 12, 12),
    ('2d21d4', 11, 10, 11, 11),
    ('2cf70c', 13, 10, 10, 10),
    ('2d02a8', 4, 13, 180, 436),
    ('2cf70c', 6, 11, 6, 6),
    ('2d0c54', 6, 6, 22, 22),
    ('2cf70c', 6, 9, 6, 6),
    ('2ced6c', 6, 12, 11, 11),
    ('2cf838', 9, 0, 12, 12),
    ('2d21d4', 11, 9, 11, 11),
    ('2cf70c', 13, 9, 9, 9),
    ('2cf70c', 8, 11, 8, 8),
    ('2d0c54', 8, 8, 17, 17),
    ('2cf70c', 8, 6, 8, 8),
    ('2ced6c', 8, 12, 11, 11),
    ('2cf838', 6, 0, 12, 12),
    ('2d21d4', 11, 6, 11, 11),
    ('2cf70c', 7, 6, 6, 6),
    ('2cf70c', 10, 11, 7, 7),
    ('2cf838', 8, 0, 11, 11),
    ('2d0c54', 7, 7, 11, 11),
    ('2cf70c', 7, 8, 7, 7),
    ('2ced6c', 7, 12, 10, 10),
    ('2d02a8', 4, 12, 184, 440),
    ('2cf70c', 5, 7, 5, 5),
    ('2d21d4', 10, 8, 10, 10),
    ('2cf70c', 9, 10, 9, 9),
    ('2cf70c', 12, 8, 8, 8),
    ('2ceae4', 4, 12, 200, 456),
    ('2d0c54', 9, 9, 26, 26),
    ('2cf70c', 9, 7, 9, 9),
    ('2ced6c', 9, 11, 10, 10),
    ('2cf838', 7, 0, 11, 11),
    ('2d21d4', 10, 7, 10, 10),
    ('2cf70c', 6, 10, 6, 6),
    ('2cf838', 9, 0, 10, 10),
    ('2d0c54', 6, 6, 22, 22),
    ('2cf70c', 6, 9, 6, 6),
    ('2ced6c', 6, 11, 7, 7),
    ('2d02a8', 4, 11, 188, 444),
    ('2d21d4', 7, 9, 7, 7),
    ('2cf70c', 8, 7, 7, 7),
    ('2cf70c', 11, 9, 9, 9),
    ('2d02a8', 4, 11, 192, 448),
    ('2d0c54', 7, 7, 17, 17),
    ('2cf70c', 7, 6, 7, 7),
    ('2ced6c', 7, 10, 8, 8),
    ('2cf838', 6, 0, 10, 10),
    ('2d21d4', 8, 6, 8, 8),
    ('2cf70c', 23, 6, 6, 6),
    ('2cf70c', 5, 8, 5, 5),
    ('2d0c54', 5, 5, 11, 11),
    ('2cf70c', 5, 7, 5, 5),
    ('2ced6c', 5, 10, 8, 8),
    ('2cf838', 7, 0, 10, 10),
    ('2d21d4', 8, 7, 8, 8),
    ('2cf70c', 11, 7, 7, 7),
    ('2cf838', 5, 0, 11, 11),
    ('2cf70c', 9, 8, 8, 8),
    ('2d0c54', 8, 8, 26, 26),
    ('2cf70c', 8, 5, 8, 8),
    ('2ced6c', 8, 10, 9, 9),
    ('2d02a8', 4, 10, 220, 476),
    ('2d21d4', 9, 5, 9, 9),
    ('2cf70c', 6, 9, 6, 6),
    ('2cf70c', 8, 10, 10, 10),
    ('2d0c54', 6, 6, 22, 22),
    ('2d1dec', 12, 10, 8, 8),
    ('2d02a8', 4, 10, 196, 452),
    ('2cf70c', 6, 8, 6, 6),
    ('2ced6c', 6, 11, 9, 9),
    ('2cf70c', 10, 5, 5, 5),
    ('2d02a8', 4, 10, 4, 4),
    ('2d21d4', 9, 8, 9, 9),
    ('2cf838', 8, 0, 8, 8),
    ('2cf70c', 7, 9, 7, 7),
    ('2d02a8', 4, 9, 216, 472),
    ('2cf70c', 6, 10, 10, 10),
    ('2d0c54', 7, 7, 17, 17),
    ('2d1dec', 12, 10, 20, 20),
    ('2cf70c', 7, 6, 7, 7),
    ('2cf70c', 7, 9, 9, 9),
    ('2d1dec', 12, 9, 16, 16)
)


def _u32(x):
    return x & 0xFFFFFFFF


def _u32le_at(buf, off):
    import struct
    if off < 0 or off + 4 > len(buf):
        raise ValueError("u32 oob %s" % off)
    return struct.unpack_from("<I", buf, off)[0]


def _i32le_at(buf, off):
    import struct
    if off < 0 or off + 4 > len(buf):
        raise ValueError("i32 oob %s" % off)
    return struct.unpack_from("<i", buf, off)[0] & 0xFFFFFFFF


def slots_from_seed(seed):
    if len(seed) < SEED_SLOT0 + N_SLOTS * 8:
        raise ValueError("seed must cover slot table at +0x120, got %d" % len(seed))
    return [_u32le_at(seed, SEED_SLOT0 + i * 8) for i in range(N_SLOTS)]


def mill_d10_ready(gap, k):
    if len(gap) < FILL_M90_GAP_OFF + 4:
        return False
    return _u32le_at(gap, FILL_M90_GAP_OFF) == ror32(C_PRE, (int(k) + 5) & 31)


def _apply(sl, gap, hpc, a, b, d, imm):
    if hpc == "2cf70c":
        sl[d] = _u32(sl[a] + sl[b])
    elif hpc == "2ced6c":
        sl[d] = _u32(sl[a] | sl[b])
    elif hpc == "2cf838":
        sl[d] = _u32(~(sl[a] | sl[b]))
    elif hpc == "2d0c54":
        sl[b] = ror32(sl[a], d)
    elif hpc == "2d21d4":
        sl[d] = _u32(sl[a] ^ sl[b])
    elif hpc == "2d02a8":
        sl[b] = _i32le_at(gap, imm)
    elif hpc == "2ceae4":
        sl[b] = _u32le_at(gap, imm)
    elif hpc == "2d1dec":
        return
    else:
        raise ValueError("unknown mill op %s" % hpc)


def mill_walk_d10_to_idx69(seed, gap, k):
    """Walk dest=10 slots through fused mill ops to 301730 idx=6/9 addends.

    Live assemble==20B on k∈{6,9,10,22,25,26} (P2065/P2066/P2070). Compound packing may
    differ by k15; this is the fused simple stream. p168 uses *(gap+468)
    (idx=9 LDRSW) rather than ROR(C8C,k); they match on live dest=10 (P2064/P2068).
    """
    sl = slots_from_seed(seed)
    sl[D10_ADD_D] = _u32(sl[D10_ADD_A] + sl[D10_ADD_B])
    p150 = p160 = None
    for hpc, a, b, d, imm in MILL_D10_TO_IDX9_OPS:
        if (hpc, a, b, imm) == IDX6_LDRSW and p150 is None:
            p150 = _u32(sl[6] + sl[8])
            p160 = sl[8] & 0xFFFFFFFF
        _apply(sl, gap, hpc, a, b, d, imm)
    if p150 is None or p160 is None:
        raise RuntimeError("idx=6 LDRSW mark not hit")
    return {
        "p150_idx6": p150,
        "p160_idx6": p160,
        "p168_idx9": _u32(sl[7] + _i32le_at(gap, 468)),
        "p148_idx9": sl[5] & 0xFFFFFFFF,
        "p158_idx9": _u32(sl[7] | sl[8]),
        "sl7_idx9": sl[7] & 0xFFFFFFFF,
        "sl8_idx9": sl[8] & 0xFFFFFFFF,
    }


# dest=9 2d7104 enter through dest=9 2dfdbc ADD s9+=s13 (P1411). No LDRSW in this prefix.
D9_7104_TO_FDBC_OPS = MILL_D10_TO_IDX9_OPS[:14]


def walk_d9_2d7104_to_2dfdbc_enter(sl):
    """dest=9 2d7104 enter -> dest=9 2dfdbc enter (p9u1417 2/2).

    mill_d10 ops[0:14]: ORN s15=~s10; s10+=s20; ROR s9,26; s10+=s14; s9+=s8;
    s14=s9|s15; s8^=s14; s6+=s8; ROR s6,22; s6+=s9; then s8/s11/s9 rewrite;
    last ADD s9+=s13. Needs sl[0,6,8,9,10,11,13,14,15,20]; sl[0] is 0 live.
    """
    out = list(sl)
    if len(out) < 21:
        raise ValueError("need sl[0..20]")
    dummy = b"\x00" * 4
    for hpc, a, b, d, imm in D9_7104_TO_FDBC_OPS:
        _apply(out, dummy, hpc, a, b, d, imm)
    return out


def s8_after_d9_2dfdbc(s6, s8, s10):
    """dest=9 2dfdbc fused: s8 = ROR32(s10+s8, 17)+s6 (p9u1260 2/2)."""
    return _u32(ror32(_u32(s10 + s8), 17) + s6)


def p150_d10_from_d9_2dfdbc(s6_fdbc_enter, gap428):
    """P1958: dest=10 serialize p150 = s6@2dfdbc enter + *(gap+428).

    dest=10 enter s13 is *(gap+432), not the 428 addend (LDRSW 432 after the ADD).
    """
    return _u32(s6_fdbc_enter + gap428)


def s8_after_d9_2e029c(s8, s13):
    """dest=9 2e029c fused last ADD: s8 = s13+s8 (p9u1417 2/2 vs 2dfe94 enter)."""
    return _u32(s8 + s13)


def s10_after_d9_2dfe94(s10, s6):
    """dest=9 2dfe94 fused first two ops: s10 = ROR32(s10, 16)+s6 (p9u1417 2/2 vs 2d7104 enter).

    Packets match dest=16 2dfe94 idx=617 (P1941 A10/B10/amt16 then A10:B6:D10). Dest=9
    serialize FDBC is idx=616; dest=9 2e029c is not idx=624 (that is dest=16 mill).

    HANDLER STRUCTURE (from p9u1239 disE94 machine code @0x2dfe94, 4 fused beats,
    each operand packet = 3 bytes [b0,b1,b2] read from x0 at p18/p10/p8/p0 in order):
      beat1 @2dfe9c  (packet p18): sl[b1] = ROR32(sl[b0], b2)          # ror w10,w10,w12
      beat2 @2dfed4  (packet p10): sl[b1] = sl[b2] + sl[b0]            # add w8,w10,w8
      beat3 @2dff08  (packet p8) : sl[b1] = sl[b2] + sl[b0]            # add w8,w10,w8
      beat4 @2dff40  (packet p0) : sl[b1] = sl[b2] ^ sl[b0]; br x10    # eor x8,x9,x8
    The s10=ROR16+s6 result below is beat1(sl10=ror(sl10,16)) folded with a later +s6.
    beat4 br x10 does NOT land on 2d7104 directly: rFe94->r7104 changes SIX slots
    (s6/s8/s9/s11/s12/s13), more than 4 beats can write, so >=1 more fused handler sits
    between 2dfe94 and 2d7104. Its packets are NOT in any offline dump, so the full
    dest=9 corridor cannot be closed offline. NEXT: real-device dump of the 4 packets
    p18/p10/p8/p0 at ADD2CF x0 for dest=9 next=2dfe94 AND follow beat4 br x10 to capture
    the intermediate handler's packets (see _fe94_x0dump.js).
    """
    return _u32(ror32(s10, 16) + s6)


def d9_2dfe94_four_beats(sl):
    """dest=9 2dfe94 全 4 拍 fused，就地改写 slot 表 (真机 _fe94_x0dump 2/2 byte-eq).

    机器码 @0x2dfe94 逐拍 (每拍 3-byte packet [A,B,D] = low/mid/high，从 x0 依次取
    p18/p10/p8/p0)。真机两样本 packet 恒为：
      beat1 p18 ROR: sl[10] = ROR32(sl[10], 16)          # [A=10,B=10,D=16]->sl[B]=ror(sl[A],D)
      beat2 p10 ADD: sl[10] = sl[6] + sl[10]             # [A=10,B=6,D=10]->sl[D]=sl[B]+sl[A]
      beat3 p8  ADD: sl[6]  = sl[17] + sl[6]             # [A=6,B=17,D=6] ->sl[D]=sl[B]+sl[A]
      beat4 p0  XOR: sl[11] = sl[10] ^ sl[11]; br x10    # [A=11,B=10,D=11]->sl[D]=sl[B]^sl[A]
    beat3 的加数是 sl[17] = unix/p40 (s17_from_unix; p2065 k=6 与 dest=9 fe94 dump).
    br x10 落点 = 0x2e0a8c (ldr x16;br x16 跳板；k15∈{9,25} compound 走廊)，其后
    到 2d7104 仍有一段 mill 改写 s6/s8/s9/s11/s12/s13，尚未离机闭合。

    sl: 长度>=18 的可变序列 (需要 sl[6],sl[10],sl[11],sl[17])。返回同一对象。
    """
    if len(sl) < 18:
        raise ValueError("need sl[0..17]")
    sl[10] = _u32(ror32(sl[10], 16))          # beat1
    sl[10] = _u32(sl[6] + sl[10])             # beat2
    sl[6] = _u32(sl[17] + sl[6])              # beat3
    sl[11] = _u32(sl[10] ^ sl[11])            # beat4
    return sl


def s17_from_unix(ts):
    """dest=9 2dfe94 beat3 addend sl[17] = unix/p40.

    mill_d10 ops[0:14] never write sl[17]; dest=9 serialize is before 2e0a8c
    LDRSW (that site overwrites s17 from gap). p2065 k=6 dest=10 sl32[17]==p40
    (mill didn't touch it). _fe94_x0dump dest=9 serialize pair s17=1788270179 /
    1788270211 (Δ32s). k15∈{9,25} dest=10 mill later rewrites sl[17] via
    0x2e0a8c — do not read dest=10 sl[17] as p40 on those k.
    """
    return int(ts) & 0xFFFFFFFF


def p160_d8_from_s8_s25(s8_fused, s25):
    """dest=8 ADD@2cf70c next=2cf70c: s8 += s25 (p9u1239 + p9u1249).

    s8_fused is dest=9 2dfdbc leave / dest=10 2cf838 enter (s8_after_d9_2dfdbc).
    s25 is sticky dest=9 2dfdbc enter through dest=8 enter (not written by mill_d10
    ops[0:14] / 2dfdbc / 2d3a0c / dest=10 2cf838).
    """
    return _u32(s8_fused + s25)


SEED_S25 = SEED_SLOT0 + 25 * 8  # 0x1E8; only seed alias (no gap, not in SO rodata)


def s25_from_seed(seed):
    """dest=8 ADD addend = sl[25] = *(seed+0x1E8). k15=9 sticky across url; k15=6/10 mill-RF."""
    return _u32le_at(seed, SEED_S25)

# -*- coding: utf-8 -*-
"""Medusa xor34-20B assemble from W limbs / seed-epoch snaps.

Live path (P999–P1058, e2e sign==device with lag=1):
  first8 = W0||W1
  mid8   = W2||W3
  hi16   = pure_replay(v90, va0=0, first8)
  last2  = compute_byte18_byte19(f12, lag)

  W0 = m90 ^ ROL(TAB[0], k)
  W1 = m8c ^ ROL(TAB[1], k)
  W2 = m88 ^ ROL(TAB[2], k)
  W3 = m84 ^ ROL(TAB[3], k)

Seed-compose m* (P1055–P1058):
  m90 = ROL(0x783cbede,k) + (*(seed+0x148)+*(seed+0x160)) @pres8
  m84 = *(seed+0x150) + ROL(0x041364df,k) @m84
  m88 = *(seed+0x158) + ROL(0xf0be337a,k) @m88
  m8c = *(seed+0x148) + *(seed+0x168) @m8c
  k   = ts→k wall formula (P1044)

Leaf board 2026-08-13 (research P998–P1201):
  ABS CLOSED: s5_prior=416, s8_old=(s8^s7), s9_old=(s7+s9), s7_final=(s7+s11),
              final_s5=ROR11(s5+(s6^s8))+s7 @NEXTPC/ORN_FN+POSTBL,
              s26/m54 from stub, m* seed-compose @epoch snaps (P1170 store-time==device),
              p150=(ROR32(p150_prior+p168,22)+preS8.val) @0x3017d8 (P1179+P1180),
              p150_prior=(H69#1.val+slot[23]) @midH ADD2CF.d7 (P1187; s23 stable @H1),
              p168_mid=(H69#1.s9+s11@Hval) @midH ADD2CF.d7 (P1188),
              p168_final=(preS8.s5^(preS8.val|s10@mid)) @2dc9c4 (P1193+P1194; preS8=midH d8 5+8),
              s10@mid=(~s7_post_e30) @ORN_STR_0x2e0de8 (P1201; after 2e0e30→2dbff8),
              s7_pre@e30==p158 (P1202) ⇒ s10=~(ROR32(p158,17)+H69#1.val),
              H69#1.val=(p150+p168)@H1enter (P1180/P1203),
              H1enter p150=ROR32(s6,22)@2d0c54 (P1246 2/2),
              H1enter p168=ROR32(s9,26)+s7@2e0e30 (P1246 2/2),
              s11@Hval==p178@Hval (P1204),
              s11@Hval=*(i32*)(slot[4]+444)@0x2dca20 (P1205); slot[4]=seed-0x4B0 ⇒ *(seed-0x2F4) (P1206),
              gap+444 STR@0x2e5074 *(slot[4]+444)=slot[5] imm=444 (P1225);
              s12=ROL32(C_S12,k); p178=(s12+s5_old)@0x2e5030 A=12,B=5 (P1225 2/2);
              s5_old=416 path: ORR@0x2ced6c after 2d02a8 A4:B20:imm416 (P1229 2/2)
  REL:        after p168_mid, ADD2CF.d8(5+8)=preS8 then br→0x2dc9c4; s10 stable mid→ORR;
              midH s10 corridor LDRSW→2e0e30→2dbff8→ORN@2e0de8;
              H69#1→0x2dc9c4: ORR A6:B11:D7; LDRSW A4:D11:imm444; EOR A7:B9:D7
  ABS OPEN:   none on xor34-f13 path given seed+gap+SO TAB/tbl (P2055).
              Gap/seed *contents* are session import (not SHA256); TAB/tbl from SO.
  Delivery:   assemble(snaps) or assemble(derive_leaves(seed,gap,k,tab)).
"""
from __future__ import annotations

import struct
from typing import Any

from .medusaEncrypt import compute_byte18_byte19
from .p9oc_field13_hi16_pure_core import pure_replay, load_ops

TAB_OFF = 0xC3040
TAB_LIVE = [431900774, 3898181300, 3785044590, 1909577684]  # *(SO+0xC3040) this mill SO pin
TBL_LIVE = 2503986788  # *(SO+0xEA900+0x3C) this mill SO pin
C_PRE = 0x783CBEDE
C_S10 = 0x041364DF
C_S9 = 0xF0BE337A
C_S12 = 0xEBA9CF07
S5_PRIOR_FINAL = 416  # ABS closed on final xor34-f13 path (P1117/P1118)
OPS = load_ops()

LEAF_BOARD_20260812: dict[str, Any] = {
    "ABS_CLOSED": [
        "s5_prior=416",
        "s8_old=(s8^s7)@EOR_2e0e24",
        "s9_old=(s7+s9)@ADD_STR_2e0ea0",
        "s7_final=(s7+s11)@ADD2CF_2cf754",
        "final_s5=(ROR((s5+(s6^s8))>>>0,11)+s7)>>>0 @NEXTPC/ORN_FN (P1158)",
        "s26/m54=u32_le(x-ss-stub[12:16]); empty->0xE0FCA100 (P336+live)",
        "m*_seed_compose@epoch_snaps (P1170 store-time; assemble==device)",
        "p150=(ROR32(p150_prior+p168,22)+preS8.val)>>>0 @0x3017d8 (P1179+P1180)",
        "p150_prior=(H69#1.val+slot[23])>>>0 midH @ADD2CF.d7 (P1187; s23 stable from H1 enter)",
        "p168_mid=(H69#1.s9+s11@Hval)>>>0 midH @ADD2CF.d7 (P1188)",
        "p168_final=(preS8.s5^(preS8.val|s10@p168_mid))>>>0 @0x2dc9c4 (P1193+P1194)",
        "s10@p168_mid=(~s7_post_e30)>>>0 @ORN_STR_0x2e0de8 (P1201)",
        "s7_pre@2e0e30==p158 (P1202); s10=~(ROR32(p158,17)+H69#1.val)",
        "H69#1.val=(p150+p168)@H1enter; s6==p150,s9==p168 (P1180/P1203)",
        "H1enter p150/s6=ROR32(s6,22)@0x2d0c54 A=6 B=6 amt=22 (P1246 2/2)",
        "H1enter p168/s9=ROR32(s9,26)+s7@0x2e0e30 p1 A9:B9:26 then ADD A9:B7:D9 (P1246 2/2)",
        "s11@Hval==p178@Hval (P1204 2/2)",
        "s11@Hval=*(i32*)(slot[4]+444)@0x2dca20 (P1205 2/2)",
        "slot[4]=seed-0x4B0 ⇒ p178@Hval=*(seed-0x2F4) (P1206 2/2)",
        "gap+444 STR@0x2e5074 *(slot[4]+444)=slot[5] (P1093/P1225; imm=444)",
        "s12@ADD=ROL32(C_S12,k) ; p178=(s12+s5_old)@0x2e5030 A=12,B=5,dest=5 (P1225 2/2)",
        "s5_old=416 via ORR@0x2ced6c after 2d02a8 A4:B20:imm416 (P1229 2/2); xor34-f13 path locks 416 (0/leftover not this path)",
        "p148_cold=*(gap+524)+((u8(himm)<<24)|s10) s4=seed-0x4B0 (P1857/P1861)",
        "s10=((u8(ld)<<8)|u8(lo))|(u8(dd)<<16) imm table by k (P1859/P1861)",
        "p158_cold=(ROR32(0x3DF5A9A5,k)+*(seed+0x1F8)) (P1910 3/3)",
        "slot[23]=*(seed+0x1D8); s27=*(seed+0x1F8) k-table persist alias (P1889)",
        "serialize p150/p160/p168=*(seed+0x150/0x160/0x168) (P1948/P1946/P1865)",
        "TAB=SO+0xC3040; tbl=*(SO+0xea900+0x3c); k=k_from_ts(ts,tbl) (P1044)",
        "gap[480:528]=ROR32(W[0:12],(k+3)&31) from SO+k (P2058 live mixed 5/5)",
        "lo=18 if k15==10 else 33 if k15==6; b=(k>>4)&1; ld=5*lo; himm=136-lo; dd=0xDD (k15 6/10)",
        "k15=9 p148 u8s ld/lo/dd/himm=168/166/88/199 (P1861+P2058); s6 still (k+3)&31",
        "lo=18 if ((ts>>3)&1) else 33; b=(ts>>4)&1 agrees on mill-pair k (P1693 81/81)",
        "s26_sticky=ROL32(0x9be0826c,(16*b-4*bit3)&31) (P1693 21/21)",
        "s25@1A84=k-table persist 5/5 mixed; s3@1A84=m70/m7c/p40 (P2024/P2058)",
        "p148 from SO+k: plant ROR32(W[11],k+3) + u8s (P2058/P2059 k∈{6,9,10,22,25,26} live)",
        "dest=10 *(seed+0x148)=p148_from_k_so (P2060 3/3); *(seed+0x1F8)=s25@1A84 (P2060 3/3)",
        "xor34-20B readable at serializer 0x265660 after mill; CALL_SER still banned",
        "search /aweme/v2/search/general/stream/ (and history_words/memory) also serialize xor34-20B at 0x265660; last2=compute_byte18_byte19(url_ts, lag=1) on stream (P2073); WRAP-armed dest=10 hunt misses these SER",
        "same-WRAP sticky STR1 can attach to some search stream SER with fill_ready; fill XOR of that STR1 gap still ≠ live first18; many search SER have no same-WRAP STR1 at all (P2074)",
        "search SER often has no STR1/SITE7/P168/D10 mill in that WRAP; P168 dest=10 mill-walk of a nearby mill ≠ stream first18 (P2075)",
        "p158@1A84=ROR32(*(SO+0xEA900),k) mill-time only (P2058 5/5); serialize still P1910",
        "1A84 m84/m88/m8c=ROR32(C84/C88/C8c,k) (P2058 5/5)",
        "fill PRE-308090: W[i]=M[i]^ROR32(TAB[i],(k+5)&31) (P2062 3/3); M=(m90,m8c,m88,m84) at seed-0x90..-0x84; h[i] at seed-0x140..-0x134; m8c=hid=310 val; last2 lag=1 f12=p40",
        "C84=ROR32(C_S10,5); C88=ROR32(C_S9,5); dest=10 m90/m84/m88=ROR32(C_PRE/C_S10/C_S9,k+5) (P2063)",
        "fill M from 3017d8: m90=ROR(C_PRE,k+5)+p160@idx6; m84=ROR(C_S10,k+5)+p150@idx6; m88=p168@idx9+ROR(C_S9,k+5)-ROR(C8C,k); m8c=p168@idx9+ROR11(p148@idx9+(p150@idx6^p158@h262)) (P2063 k=9; P2064 mixed k∈{10,22,25})",
        "301730: LDRSW then ADD then ORR. idx=6 p150=sl6+sl8; idx=9 p168=sl7+ROR(C8C,k); *(gap+468)=ROR(C8C,k) (P2064)",
        "dest=10 mill-walk: slot[i]=*(seed+0x120+i*8); dest=9 ADD sl9+=sl15; fused mill ops k-invariant on k∈{6,9,10,22,25,26} (P2065/P2066/P2070); compound grouping differs (k15=9/25 uses 2e0a8c/2dda90, k15=6/10 including k=22/26 uses 2d4150/2d7104/2da29c) but fused simples match; p160@idx6=sl8; p158@h262=sl7|sl8 @idx9 enter",
        "derive_leaves(seed,gap) uses SER-epoch raw W when fill slots==proto first16 in seed (P2079); else fill XOR when andHits==ROR(TAB,k+5); else dest=10 mill-walk when m90==ROR(C_PRE,k+5); else force fill XOR with caller k (P2077 mill-wrap SER after H moved)",
        "serialize classic compose still miss first18; CALL_SER still banned",
        "TAB_LIVE=SO+0xC3040 pin; dest=10 seed+gap (no tab/k) mill-walk==live 20B (P2069)",
        "dest=10 mill-walk live 20B k∈{22,26} (k15=6/10 families) P2070",
        "sticky k: gap+0x1d8==ROR(C_S9,k+5) and gap+0x1dc==ROR(C_PRE,k+5) after H/m90 move (P2078)",
        "flavor16 mill[32:48] not an xor34-20B assemble input (P2078)",
        "search stream mill-wrap SER first18 = fill slots already W (gap+0x420); assemble_from_w(M) lag=1 f12=url_ts; gate=W also in seed (P2079 2+ bursts)",
    ],
    "REL_CLOSED": [
        "early_s5=(ROL(C_S12,k)+416)",
        "s8@89→ROR26",
        "s26==m54",
        "mid ~12/~11",
        "final s11=MVN(~s5)@2cf880",
        "s9_old=~s10",
        "s5==seed+0x148 / s7==seed+0x158",
        "s10@m84=ROL(C_S10,k) / s9@m88=ROL(C_S9,k)",
        "s6_after_6plus9=(p150_prior+p168) @ADD2CF dest6",
        "H1enter s6=ROR32(s6_pre,22)@2d0c54 (P1246 2/2); s6_pre still ABS",
        "H1enter s9=ROR32(s9_pre,26)+s7@2e0e30 (P1246 2/2); s7 already H1 at 2e0e30 enter",
        "H1enter s8=(s8+s6)@0x2e4abc then +s12@ADD2CF dest=8 (P1253 p1eqD8 2/2, P1250/P1251 s8+s12 2/2); s12@D8=*(gap+440) (P1259 2/2); s6_pre still ABS",
        "last 0x2dfdbc after dest=10 next=0x2ced6c: s13=*(gap+436), s6=ROR32(s6+s11,22)+s9 (P1248 pkt 2/2, P1249 p4=ADD leave 1/1; no s5/s7/s9/s23 write)",
        "2e4abc→op647 0x2e0da8: s12=~(s6|s0), s11^=s6 (P1254/P1255 2/2); then op588 0x2dedec: s6=s6+s7 (E30 s6 2/2), s11=~s8 (D8 2/2), p2 s7=s10+s11 then pc+4→0x2e0e30 (P1257)",
        "s6_mid@p150=ROR32(s6_6plus9,22)=ROL32(s6_6plus9,10)",
        "slot8@p150_writer==preS8.val",
        "midH: ADD2CF.d8 (s5+s8)=preS8 then br→0x2dc9c4 (P1189/P1192/P1194)",
        "0x2dc9c4: ORR(preS8.val|s10)→slot9 then EOR(^s5)→slot9; s10 stable mid→ORR",
        "preS8.s5==p148; preS8.val==(p148+p160_old); ORR s8==preS8.val (P1194 2/2)",
        "s7_post_e30=(ROR32(s7_pre,17)+s6)@0x2e0e30; s10=(~s7)@ORN_0x2e0de8 (P1201)",
        "s6@2e0e30==H69#1.val (stable after H1 dest6; 2/2 clean)",
        "s7_pre@e30==p158; soft@H_2CF70C prev+s8 (P1202 2/2)",
        "H69#1→0x2dc9c4 LDRSW A4:D11:imm444→s11 (P1205)",
        "0x2dcd34 after early 2e0e30 pc+4: LDRSW s12=*(gap+440); ADD s5=s5+s7; EOR s10=s10^s8; ADD s9=s9+s10; smaddl pc+5 (P1259 2/2)",
        "pre-dest10 0x2e0e30 after dest=9: s9=ROR32(s9,26)+s10 (P1261 2/2); s5/s7/s23 already stable; s11/s12 still change before dest=10",
        "dest=16→2d02a8 A4:B5:imm524 s5=*(gap+524); 2d0c54 ROR s12=ROR32(s12,28); BL@0x30465c via 0x2ddc6c: dest=10 s5=s5+s21, tmp s12=s12+s14, tmp s6=s6+s12+s14 (P1268 2/2 distinct PIDs); s21 unchanged by BL",
        "dest=16 s21=(*(gap+420)<<24)|s10 (P1282 2/2): 2da158 LDR A4:B20:imm420 → 2e39c4 LSL A20:D21:amt24 → 2da158 ORR A10:B21:D21; s10 already stable at dest=6→LSL@0x2cedfc enter",
        "dest=6 s10=s10_mid|(s13<<16) (P1293 2/2): 2d9448 LSL A13:D13:amt16 then 2e1a84 skip+5 ORR A10:B13:D10",
        "s10_mid=(ld<<8)|*(gap+332) (P1294/P1295/P1297/P1298 2/2): LSL A10:D10:amt8 then 2de4c8 ORR A10:B18:D10; 2d268c LDRSW A4:B18:imm332 writes s18=*(gap+332)=*(seed-0x364) (s18 not yet lo at 268c enter); simple 2ced6c D=10 not dispatched",
        "s13@2da158=*(gap+imm) via 2e39c4 LDRSW A4:B13:imm∈{316,320} mill=0xDD this epoch (P1302 2/2); LSL A8:D8:amt8 first then LDR; simple 2d02a8 B=13 not dispatched",
    ],
    "ABS_OPEN": [],
    "MEM_IMPORT": [
        "k-table persist VALUES m60/m64/m70/m7c are per-wrap mill state (alias by k15 is closed P2024/P2058 5/5; dest=10 s27 copy = s25@1A84 P2060 3/3; flipping m60/m64/m70/m7c in dest=10 gap does not change mill-walk 20B P2072; mill LDRSW imms miss 0x434..0x450)",
        "seed +0x150/+0x160/+0x168 still change after dest=10 (p150 writer 0x3017d8); TAB_LIVE/TBL_LIVE pin this mill SO (P2069)",
        "search first18: mill-wrap SER first18 = fill XOR after H moved (P2077) or SER-epoch raw W when fill slots copied into seed (P2079 stream ≥2); k after H-move from gap+0x1d8/0x1dc (P2078); flavor16 not on xor34-20B (P2078); mill-less WRAP first18 still miss; last2=url_ts lag=1",
    ],
    "delivery": "assemble_from_material_dict mill-walks dest=10 seed+gap (P2067); k inverted from mill gates, fill andHits, or sticky C_S9/C_PRE at gap+0x1d8/0x1dc (P2068/P2078); TAB_LIVE default (P2069); k∈{22,26} live mill-walk (P2070); Cronet URL pair (P2071); k-table VALUES not on dest=10 20B (P2072); search SER xor34+last2 (P2073); mill-wrap SER fill XOR after H moved (P2077); flavor16 not on xor34-20B (P2078); stream mill-wrap SER-epoch raw W when fill slots in seed (P2079); derive_leaves same paths; W/snaps still accepted; SHA256 cold is placeholder not live-exact; live-exact needs seed+gap import",
    "research_cutoff": "P9U2079",
}


def u32le(x: int) -> bytes:
    return struct.pack("<I", x & 0xFFFFFFFF)


def rol32(x: int, k: int) -> int:
    k &= 31
    x &= 0xFFFFFFFF
    return ((x << k) | (x >> (32 - k))) & 0xFFFFFFFF


def ror32(x: int, k: int) -> int:
    k &= 31
    x &= 0xFFFFFFFF
    return ((x >> k) | (x << (32 - k))) & 0xFFFFFFFF


def p150_h1_from_s6_ror22(s6_pre: int) -> int:
    """P1246: H1enter p150/slot[6] = ROR32(s6, 22) at 0x2d0c54 A=6 B=6 amt=22 (2/2)."""
    return ror32(s6_pre, 22)


def p168_h1_from_s9_ror26_s7(s9_pre: int, s7: int) -> int:
    """P1246: H1enter p168/slot[9] = ROR32(s9, 26) + s7 at 0x2e0e30 (2/2).

    Fused p1 A=9 B=9 amt=26 then p2 A=9 B=7 D=9 ADD.
    """
    return (ror32(s9_pre, 26) + (s7 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s6_after_dest10_2dfdbc(s6: int, s11: int, s9: int) -> int:
    """P1248/P1249: last 0x2dfdbc after ADD2CF dest=10, BR next=0x2ced6c.

    Sequential: LDRSW s13=*(slot[4]+436); s6 = ROR32(s6+s11, 22) + s9.
    Handler writes only s6 and s13 (not s5/s7/s9/s23).
    """
    return (ror32((s6 + s11) & 0xFFFFFFFF, 22) + (s9 & 0xFFFFFFFF)) & 0xFFFFFFFF


def p160_h1_from_s8_s12(s8_pre: int, s12: int) -> int:
    """P1250/P1251: H1enter p160/slot[8] = s8 + s12 at ADD2CF dest=8 next=0x2ceae4.

    Confirmed P1250 2/2 and P1251 dest=8 brute add(s8,s12).
    s8_pre is dest=8 enter = (s8+s6)@0x2e4abc (P1253 2/2).
    """
    return ((s8_pre & 0xFFFFFFFF) + (s12 & 0xFFFFFFFF)) & 0xFFFFFFFF


def p160_h1_from_s8_s6_s12(s8: int, s6: int, s12: int) -> int:
    """P1253+P1251: H1enter p160 = (s8+s6)@0x2e4abc + s12@dest=8."""
    return p160_h1_from_s8_s12((s8 + s6) & 0xFFFFFFFF, s12)


def s12_from_orn_s6_s0(s6: int, s0: int = 0) -> int:
    """P1255: 0x2e0da8 p1 A=6 C=0 D=12: s12 = ~(s6 | s0) (2/2). Corridor s0==0.

    Intermediate; overwritten before dest=8.
    """
    return (~((s6 | s0) & 0xFFFFFFFF)) & 0xFFFFFFFF


def s11_from_eor_s6_2e0da8(s11: int, s6: int) -> int:
    """P1255: 0x2e0da8 p2 A=11 C=6 D=11: s11 = s11 ^ s6 (2/2). Intermediate."""
    return (s11 ^ s6) & 0xFFFFFFFF


def s6_e30_from_s6_s7_2dedec(s6: int, s7: int) -> int:
    """P1257: 0x2dedec p1 A=7 C=6 D=6: s6 = s6 + s7 equals dest=8/E30 s6 (2/2)."""
    return ((s6 & 0xFFFFFFFF) + (s7 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s11_d8_from_s8(s8_pre: int) -> int:
    """P1257: 0x2dedec p4 ORN A=8 C=0 D=11: s11 = ~(s8|0) = ~s8 equals dest=8 s11 (2/2)."""
    return (~(s8_pre & 0xFFFFFFFF)) & 0xFFFFFFFF


def s5_tmp_from_gap524(gap524_i32: int) -> int:
    """P1264/P1267: dest=16→2d02a8 A=4 B=5 imm=524: s5 = *(i32*)(slot[4]+524) (2/2).

    Intermediate; overwritten by native BL@0x2ddc6c to dest=10 s5.
    slot[4]=gap=seed-0x4B0 ⇒ *(seed-0x2A4).
    """
    return gap524_i32 & 0xFFFFFFFF


def s12_ror28_at_2d0c54(s12: int) -> int:
    """P1266/P1267: 0x2d0c54 after 2d02a8: s12 = ROR32(s12, 28) A=12 D=12 amt=28 (2/2).

    Visible at 0x2ddc68 enter; overwritten by the following native BL.
    """
    return ror32(s12, 28)


def s5_d10_from_s5_s21(s5_gap524: int, s21: int) -> int:
    """P1268: dest=10 / p148_h1_pre_2dcd34 s5 = s5 + s21 inside BL@0x30465c (2/2).

    s5_gap524 is *(gap+524) at dest=16→2d02a8 (P1264/P1267 enterEqLd).
    s21 is dest=16 s21 = (*(gap+420)<<24)|s10 (P1282).
    """
    return ((s5_gap524 & 0xFFFFFFFF) + (s21 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s20_tmp_from_gap420(gap420_i32: int) -> int:
    """P1282: 2da158 LDRSW A=4 B=20 imm=420: s20 = *(i32*)(slot[4]+420) (2/2).

    Consumed immediately by 2e39c4 LSL A=20 D=21 amt=24.
    """
    return gap420_i32 & 0xFFFFFFFF


def s21_d16_from_gap420_s10(gap420_i32: int, s10: int) -> int:
    """P1282: dest=16 / dest=8→2cf70c s21 = (*(gap+420) << 24) | s10 (2/2).

    Chain after dest=6→LSL@0x2cedfc: 2da158 LDR A4:B20:imm420, 2e39c4 LSL A20:D21:amt24,
    then 2da158 ORR A10:B21:D21. s10 is already this value at dest=6 LSL enter.
    Do not hook BR 0x2da1c8 / 0x2e3a30.
    """
    hi = ((gap420_i32 & 0xFFFFFFFF) << 24) & 0xFFFFFFFF
    return (hi | (s10 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s13_tmp_from_lsl16(s13: int) -> int:
    """P1290/P1293: 2d9448 LSL A=13 D=13 amt=16: s13 = s13 << 16 (2/2).

    s13 at 2da158 / 2d9448 enter is *(gap+imm) from 2e39c4 LDR B=13 (P1302, 0xDD this epoch).
    Consumed by 2e1a84 ORR D=10.
    """
    return ((s13 & 0xFFFFFFFF) << 16) & 0xFFFFFFFF


def s13_tmp_from_gap_ldr(gap_i32: int) -> int:
    """P1302: 2e39c4 LDRSW A=4 B=13 imm∈{316,320}: s13 = *(i32*)(slot[4]+imm) (2/2).

    Second 2e39c4 after 2de4c8 (LSL A8:D8:amt8 first). mill=221 both live wraps.
    Simple 2d02a8 B=13 not dispatched. slot[4]=gap=seed-0x4B0.
    Do not hook BR 0x2e3a30 / 0x2de5a0.
    """
    return gap_i32 & 0xFFFFFFFF


def s10_d6_from_mid_s13(s10_mid: int, s13: int) -> int:
    """P1293: dest=6 s10 = s10_mid | (s13 << 16) (2/2).

    After AND#8 LDR B=10: 2d9448 LSL A13:D13:amt16, then 2e1a84 fused skip+5
    ORR A10:B13:D10. s10_mid is FLIP1 = (ld<<8)|lo (P1295).
    Live: (23058, 221)→14506514, (42273, 221)→14525729.
    Do not hook BR 0x2d94fc / 0x2e1af0 / 0x2cedb4.
    """
    return ((s10_mid & 0xFFFFFFFF) | (((s13 & 0xFFFFFFFF) << 16) & 0xFFFFFFFF)) & 0xFFFFFFFF


def s10_flip1_lsl8_from_ldr(s10_ldr: int) -> int:
    """P1294/P1295: after 2e39c4, LSL A=10 D=10 amt=8: s10 = ld << 8 (2/2).

    Visible at 2d268c enter (s10eqLsl8). 2d268c itself does not write s10.
    Live: 90→23040, 165→42240.
    """
    return ((s10_ldr & 0xFFFFFFFF) << 8) & 0xFFFFFFFF


def s10_flip1_from_ldr_lo(s10_ldr: int, lo: int) -> int:
    """P1297/P1298: s10_mid / FLIP1 = (ld << 8) | s18 (2/2).

    LSL A10:D10:amt8 after 2e39c4, then 2de4c8 fused ORR A10:B18:D10.
    s18 = *(gap+332) from 2d268c LDRSW A4:B18:imm332 (P1298).
    Live: (90, 18)→23058, (165, 33)→42273.
    Do not hook BR 0x2d2778 / 0x2e3a30 / 0x2dd544.
    """
    return (s10_flip1_lsl8_from_ldr(s10_ldr) | (lo & 0xFFFFFFFF)) & 0xFFFFFFFF


def s18_tmp_from_gap332(gap332_i32: int) -> int:
    """P1298: 2d268c LDRSW A=4 B=18 imm=332: s18 = *(i32*)(slot[4]+332) (2/2).

    Consumed by 2de4c8 ORR A10:B18:D10 then overwritten by 2de4c8 LDR B=18.
    slot[4]=gap=seed-0x4B0 ⇒ *(seed-0x364).
    """
    return gap332_i32 & 0xFFFFFFFF


def s10_flip1_from_ldr_gap332(s10_ldr: int, gap332_i32: int) -> int:
    """P1298: s10_mid = (ld << 8) | *(gap+332) (2/2)."""
    return s10_flip1_from_ldr_lo(s10_ldr, s18_tmp_from_gap332(gap332_i32))


def s10_d6_from_ldr_lo_s13(s10_ldr: int, lo: int, s13: int) -> int:
    """P1293+P1295: dest=6 s10 = ((ld << 8) | lo) | (s13 << 16) (2/2).

    Live: (90, 18, 221)→14506514, (165, 33, 221)→14525729.
    """
    return s10_d6_from_mid_s13(s10_flip1_from_ldr_lo(s10_ldr, lo), s13)


def s12_tmp_from_ror28_s14(s12: int, s14: int) -> int:
    """P1268: POST-BL s12 = ROR32(s12, 28) + s14 (2/2). Intermediate; overwritten before dest=13."""
    return (ror32(s12, 28) + (s14 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s6_tmp_from_s6_s12_s14(s6: int, s12_ror28: int, s14: int) -> int:
    """P1268: POST-BL s6 = s6 + s12 + s14 = s6 + POST.s12 (2/2). Intermediate before dest=10."""
    return ((s6 & 0xFFFFFFFF) + (s12_ror28 & 0xFFFFFFFF) + (s14 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s9_d10_from_s9_s10(s9_pre: int, s10: int) -> int:
    """P1261: dest=10 s9 = ROR32(s9, 26) + s10 at 0x2e0e30 after dest=9 (2/2).

    Same handler as late H1 s9, but this visit is BEFORE dest=10; p2 ADD uses s10 not s7.
    """
    return (ror32(s9_pre, 26) + (s10 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s12_d8_from_gap440(gap440_i32: int) -> int:
    """P1259: dest=8 s12 = *(i32*)(slot[4]+440) LDRSW A=4 B=12 imm=440 (2/2).

    slot[4]=gap=seed-0x4B0 ⇒ *(seed-0x2F8). Adjacent to p178@Hval at seed-0x2F4.
    """
    return gap440_i32 & 0xFFFFFFFF


def s5_d8_from_s5_s7(s5_enter: int, s7: int) -> int:
    """P1259: dest=8/H1 s5 = s5+s7 at 0x2dcd34 p2 ADD A=5 C=7 D=5 (2/2).

    s7 is already H1 (early 2e0e30). s5_enter is dest=10 s5 = *(gap+524)+s21 (P1268).
    """
    return ((s5_enter & 0xFFFFFFFF) + (s7 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s10_d8_from_s10_s8(s10_enter: int, s8_pre: int) -> int:
    """P1259: dest=8 s10 = s10^s8 at 0x2dcd34 p3 EOR A=10 C=8 D=10 (2/2).

    s10_enter is early 2e0e30 p3 (H1 s7 + s12_orn). s8 is dest=8 pre.
    """
    return (s10_enter ^ (s8_pre & 0xFFFFFFFF)) & 0xFFFFFFFF


def s9_d8_from_s9_s10(s9_enter: int, s10_d8: int) -> int:
    """P1259: dest=8 s9 = s9+s10 after EOR, 0x2dcd34 p4 ADD A=9 C=10 D=9 (2/2).

    This dest=8 s9 is s9_pre for late 2e0e30 H1 s9. s9_enter is dest=10 enter s9 (ABS).
    """
    return ((s9_enter & 0xFFFFFFFF) + (s10_d8 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s7_h1_from_s10_s11_s8(s10: int, s11: int, s8_pre: int) -> int:
    """P1257 mill + P1258 live 2/2: H1 s7 = ROR32(s10+s11, 11) + s8.

    2dedec p2 s7=s10+s11 then early 0x2e0e30 ROR amt=11 dest=7 ADD s8.
    s10/s11 at 2dedec enter; s8 is dest=8 pre.
    """
    s7 = ((s10 & 0xFFFFFFFF) + (s11 & 0xFFFFFFFF)) & 0xFFFFFFFF
    return (ror32(s7, 11) + (s8_pre & 0xFFFFFFFF)) & 0xFFFFFFFF


def p150_from_s6_pres8(s6_after_6plus9: int, pres8_val: int) -> int:
    """P1179: p150 = ROR32(s6@ADD2DD_after_6plus9, 22) + preS8.val."""
    return (ror32(s6_after_6plus9, 22) + (pres8_val & 0xFFFFFFFF)) & 0xFFFFFFFF


def p150_from_prior_p168_pres8(
    p150_prior: int, p168: int, pres8_val: int
) -> int:
    """P1179+P1180: p150 = ROR32(p150_prior + p168, 22) + preS8.val."""
    s6 = (p150_prior + (p168 & 0xFFFFFFFF)) & 0xFFFFFFFF
    return p150_from_s6_pres8(s6, pres8_val)


def p150_prior_from_h69_s23(h69_1_val: int, s23: int) -> int:
    """P1187: p150_prior = H69#1.val + slot[23] (s23 stable from H69#1 enter)."""
    return ((h69_1_val & 0xFFFFFFFF) + (s23 & 0xFFFFFFFF)) & 0xFFFFFFFF


def p168_mid_from_h69_s11(h69_1_s9: int, s11_at_hval: int) -> int:
    """P1188: p168_mid = H69#1.s9 + slot[11] when seed+150 first equals H69#1.val."""
    return ((h69_1_s9 & 0xFFFFFFFF) + (s11_at_hval & 0xFFFFFFFF)) & 0xFFFFFFFF


def p168_final_from_s5_s8_s10(s5: int, s8: int, s10: int) -> int:
    """P1193: p168_final = (s5 ^ (s8 | s10)) at 0x2dc9c4 (ORR dest9 then EOR dest9)."""
    return ((s5 & 0xFFFFFFFF) ^ ((s8 & 0xFFFFFFFF) | (s10 & 0xFFFFFFFF))) & 0xFFFFFFFF


def p168_final_from_pres8_s10(pres8_s5: int, pres8_val: int, s10_at_mid: int) -> int:
    """P1194: p168_final = (preS8.s5 ^ (preS8.val | s10@p168_mid)); preS8 from midH ADD2CF.d8."""
    return p168_final_from_s5_s8_s10(pres8_s5, pres8_val, s10_at_mid)


def s7_post_e30_from_pre(s7_pre: int, s6: int) -> int:
    """P1201: compound@0x2e0e30 ROR s7 amt17 then ADD A7:B6:D7."""
    return (ror32(s7_pre, 17) + (s6 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s10_mid_from_s7_post(s7_post_e30: int) -> int:
    """P1201: s10@p168_mid = (~s7_post_e30) at ORN_STR@0x2e0de8."""
    return (~(s7_post_e30 & 0xFFFFFFFF)) & 0xFFFFFFFF


def s10_mid_from_s7_pre_s6(s7_pre: int, s6: int) -> int:
    """P1201: s10@mid from s7_pre@2e0e30 enter and s6."""
    return s10_mid_from_s7_post(s7_post_e30_from_pre(s7_pre, s6))


def s10_mid_from_p158_h69(p158: int, h69_1_val: int) -> int:
    """P1202: s7_pre@e30==p158; s10=~(ROR32(p158,17)+H69#1.val)."""
    return s10_mid_from_s7_pre_s6(p158, h69_1_val)


def s12_from_k(k: int) -> int:
    """P1225: slot[12] at ADD@0x2e5030 = ROL32(0xeba9cf07, k)."""
    return rol32(C_S12, k)


def p178_hval_from_s12_s5(s12: int, s5_old: int) -> int:
    """P1225: p178/gap+444 = (s12 + s5_old) stored @0x2e5074 after ADD dest=5."""
    return ((s12 & 0xFFFFFFFF) + (s5_old & 0xFFFFFFFF)) & 0xFFFFFFFF


def p178_hval_from_k_s5(k: int, s5_old: int) -> int:
    """P1225: p178 = ROL32(C_S12, k) + s5_old. s5_old still an ABS leaf."""
    return p178_hval_from_s12_s5(s12_from_k(k), s5_old)


def p178_hval_from_gap444(gap_base_or_word: int, *, is_word: bool = True) -> int:
    """P1205+P1206: p178/s11@Hval = *(i32*)(seed-0x4B0+444) = *(seed-0x2F4).

    If ``is_word``, ``gap_base_or_word`` is already the u32 at that address.
    """
    return gap_base_or_word & 0xFFFFFFFF


def p178_hval_off() -> int:
    """Byte offset from seed to the p178@Hval source word."""
    return -0x2F4


def bitlen(x: int) -> int:
    x &= 0xFFFFFFFF
    n = 0
    while x:
        n += 1
        x >>= 1
    return n


def k_from_ts(ts: int, tbl: int) -> int:
    """unix wall → k (P1044). tbl typically *(SO+0xea900+0x3c)."""
    imm8 = [-1, 6, 3, 5][(ts >> 2) & 3]
    s8 = (ts + imm8) & 7
    s10 = 8 - s8
    imm_add = {2: -1, 3: 2, 4: 25, 6: 3}[s10]
    s6 = (ts + imm_add) & 31
    return bitlen((tbl >> s6) & 0xFFFFFFFF) - 5


def k_from_khronos(khronos: int, tbl: int) -> int:
    """Mill-less xor34 AND-mill k from proto khronos. Live 4/4.

    s6 = (ts + X) & 31, X = 0 if (ts>>3)&1 else 3;
    k = bitlen(tbl >> s6) - 5.
    """
    ts = int(khronos)
    x = 0 if (ts >> 3) & 1 else 3
    s6 = (ts + x) & 31
    return bitlen((tbl >> s6) & 0xFFFFFFFF) - 5


def m_from_seed_snaps(
    *,
    p148_pres8: int,
    p160_pres8: int,
    p150: int,
    p158: int,
    p148_m8c: int,
    p168_m8c: int,
    k: int,
) -> tuple[int, int, int, int]:
    s8 = (p148_pres8 + p160_pres8) & 0xFFFFFFFF
    m90 = (rol32(C_PRE, k) + s8) & 0xFFFFFFFF
    m84 = (p150 + rol32(C_S10, k)) & 0xFFFFFFFF
    m88 = (p158 + rol32(C_S9, k)) & 0xFFFFFFFF
    m8c = (p148_m8c + p168_m8c) & 0xFFFFFFFF
    return m90, m8c, m88, m84


def w_from_m_and_k(
    m90: int, m8c: int, m88: int, m84: int, k: int, tab: list[int]
) -> tuple[int, int, int, int]:
    h = [rol32(t, k) for t in tab]
    return (
        (m90 ^ h[0]) & 0xFFFFFFFF,
        (m8c ^ h[1]) & 0xFFFFFFFF,
        (m88 ^ h[2]) & 0xFFFFFFFF,
        (m84 ^ h[3]) & 0xFFFFFFFF,
    )


def w_from_fill_m_and_k(
    m90: int, m8c: int, m88: int, m84: int, k: int, tab: list[int]
) -> tuple[int, int, int, int]:
    """P2062: fill-window W = M ^ ROR32(TAB, k+5) at PRE-308090."""
    amt = (int(k) + 5) & 31
    h = [ror32(int(t), amt) for t in tab[:4]]
    return (
        (m90 ^ h[0]) & 0xFFFFFFFF,
        (m8c ^ h[1]) & 0xFFFFFFFF,
        (m88 ^ h[2]) & 0xFFFFFFFF,
        (m84 ^ h[3]) & 0xFFFFFFFF,
    )


def _coerce_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, str):
        text = value.strip()
        base = 16 if text.lower().startswith(("0x", "+0x", "-0x")) else 10
        try:
            return int(text, base)
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc


def assemble_from_material_dict(
    material: dict[str, Any],
    *,
    timestamp: int | None = None,
) -> bytes:
    """Assemble xor34-20B from a static closure dict or legacy seed-snap dict.

    Supported forms:
      - flat or nested ``w0..w3`` / ``w`` object
      - compose/closure material ``p148_pres8,p160_pres8,p150,p158,p148_m8c,p168_m8c``
        plus ``tab`` and ``k`` or ``tbl``; nested ``preS8/snap84/snap88/snap8c`` aliases
        remain accepted for backward compatibility.
      - seed+gap mill leaves (``seed``/``gap`` hex or bytes, plus ``tab`` or ``so``)
      - dest=10 mill-walk when ``gap`` m90==ROR(C_PRE,k+5); f12 defaults to seed+0x40 unless ``f12`` is set
      - k may be omitted when dest=10 mill gates or fill andHits invert uniquely (P2068)
      - tab/so may be omitted; TAB_LIVE (this mill SO+0xC3040 pin) is the default (P2069)
    """
    if not isinstance(material, dict) or not material:
        raise ValueError("material must be a non-empty object")

    lag = _coerce_int(material.get("lag", 1), "lag")
    f12_raw = material.get("f12", material.get("ts", material.get("wall_ts", timestamp)))
    f12 = None if f12_raw is None else _coerce_int(f12_raw, "f12")

    first16_raw = material.get("first16") or material.get("medusa_first16")
    if first16_raw is not None:
        if f12 is None:
            raise ValueError("f12 must be an integer")
        if isinstance(first16_raw, (bytes, bytearray)):
            raw16 = bytes(first16_raw)
        elif isinstance(first16_raw, str):
            text = first16_raw.strip()
            if text.startswith("hex:"):
                raw16 = bytes.fromhex(text[4:])
            elif len(text) == 32:
                raw16 = bytes.fromhex(text)
            else:
                from ..models import decode_bytes

                decoded = decode_bytes(text, "first16")
                raw16 = decoded or b""
        else:
            raise ValueError("first16 must be bytes or hex")
        if len(raw16) != 16:
            raise ValueError("first16 must contain exactly 16 bytes")
        return field13_20b_from_first16(raw16, f12, lag=lag)

    mill_ws = material.get("mill_ws") or material.get("workspace") or material.get("medusa_mill_ws")
    if mill_ws is not None:
        if f12 is None:
            raise ValueError("f12 must be an integer")
        return field13_20b_from_first16(first16_from_ws(_coerce_hex_blob(mill_ws, "mill_ws")), f12, lag=lag)

    wide_raw = material.get("wide64") or material.get("wide") or material.get("medusa_wide64")
    if wide_raw is not None:
        if f12 is None:
            raise ValueError("f12 must be an integer")
        return assemble_from_wide64(_coerce_hex_blob(wide_raw, "wide64"), f12, lag=lag)

    ab_raw = material.get("ab32") or material.get("A||B")
    if ab_raw is not None:
        if f12 is None:
            raise ValueError("f12 must be an integer")
        return field13_20b_from_first16(first16_from_ab32(_coerce_hex_blob(ab_raw, "ab32")), f12, lag=lag)

    w = material.get("w") if isinstance(material.get("w"), dict) else {}
    if all(key in material or key in w for key in ("w0", "w1", "w2", "w3")):
        if f12 is None:
            raise ValueError("f12 must be an integer")
        return assemble_from_w(
            _coerce_int(material.get("w0", w.get("w0")), "w0"),
            _coerce_int(material.get("w1", w.get("w1")), "w1"),
            _coerce_int(material.get("w2", w.get("w2")), "w2"),
            _coerce_int(material.get("w3", w.get("w3")), "w3"),
            f12,
            lag=lag,
        )

    so = material.get("so") or material.get("libmetasec")
    tab = material.get("tab") or material.get("TAB")
    if (not isinstance(tab, (list, tuple)) or len(tab) < 4) and so is not None:
        from .medusa_field13_leaves import load_tab_from_so, _as_bytes

        tab = load_tab_from_so(_as_bytes(so, "so"))
    if not isinstance(tab, (list, tuple)) or len(tab) < 4:
        tab = TAB_LIVE

    from .medusa_field13_leaves import (
        maybe_snaps_from_material,
        fill_gap_ready,
        mill_d10_ready,
        k_from_mill_d10_gap,
        k_from_fill_gap,
        k_from_sticky_gap,
        _as_bytes,
        u32le_at,
    )

    gap_raw = material.get("gap") or material.get("medusa_gap")
    seed_raw = material.get("seed") or material.get("medusa_seed")
    tab4 = [int(x) for x in tab[:4]]
    gap_bytes = _as_bytes(gap_raw, "gap") if gap_raw is not None else None

    if "k" in material:
        k = _coerce_int(material["k"], "k")
    else:
        k = None
        if gap_bytes is not None:
            k = k_from_mill_d10_gap(gap_bytes)
            if k is None:
                k = k_from_fill_gap(gap_bytes, tab4)
            if k is None:
                k = k_from_sticky_gap(gap_bytes)
        if k is None:
            tbl = material.get("tbl", material.get("table", material.get("tbl_u32")))
            if tbl is None and so is not None:
                from .medusa_field13_leaves import load_tbl_from_so

                tbl = load_tbl_from_so(_as_bytes(so, "so"))
            if tbl is None:
                tbl = TBL_LIVE
            wall_ts = material.get("wall_ts", material.get("ts", timestamp))
            if wall_ts is None:
                raise ValueError("material needs k, mill/fill-invertible gap, or tbl+ts for k_from_ts")
            k = k_from_ts(_coerce_int(wall_ts, "wall_ts"), _coerce_int(tbl, "tbl"))

    if gap_bytes is not None:
        if fill_gap_ready(gap_bytes, k, tab4):
            if f12 is None:
                raise ValueError("f12 must be an integer")
            seed_bytes = _as_bytes(seed_raw, "seed") if seed_raw is not None else b""
            from qishen_pure._engine.medusa_field13_leaves import (
                fill_m_from_gap,
                fill_slots_hold_ser_w,
            )

            if seed_bytes and fill_slots_hold_ser_w(seed_bytes, gap_bytes):
                m90, m8c, m88, m84 = fill_m_from_gap(gap_bytes)
                return assemble_from_w(m90, m8c, m88, m84, f12, lag=lag)
            return assemble_from_fill_gap(gap_bytes, k, tab4, f12, lag=lag)
        if seed_raw is not None and mill_d10_ready(gap_bytes, k):
            seed_bytes = _as_bytes(seed_raw, "seed")
            f12_m = f12
            if "f12" not in material and len(seed_bytes) >= 0x44:
                f12_m = u32le_at(seed_bytes, 0x40)
            if f12_m is None:
                raise ValueError("f12 must be an integer")
            return assemble_from_seed_gap(seed_bytes, gap_bytes, k, tab4, f12_m, lag=lag)
        from qishen_pure._engine.medusa_field13_leaves import FILL_M90_GAP_OFF

        if len(gap_bytes) >= FILL_M90_GAP_OFF + 16:
            if f12 is None:
                raise ValueError("f12 must be an integer")
            return assemble_from_fill_gap(gap_bytes, k, tab4, f12, lag=lag)

    derived = maybe_snaps_from_material(material, k=k)
    if derived is not None:
        material = {**material, **derived}

    pre = material.get("preS8") if isinstance(material.get("preS8"), dict) else {}
    s84 = material.get("snap84") if isinstance(material.get("snap84"), dict) else {}
    s88 = material.get("snap88") if isinstance(material.get("snap88"), dict) else {}
    s8c = material.get("snap8c") if isinstance(material.get("snap8c"), dict) else {}

    def _pick(*keys: str, nests: tuple[dict[str, Any], ...] = ()) -> int:
        for key in keys:
            if key in material:
                return _coerce_int(material[key], key)
            for nest in nests:
                if key in nest:
                    return _coerce_int(nest[key], key)
        raise ValueError(f"missing key: {keys[0]}")

    if f12 is None:
        raise ValueError("f12 must be an integer")
    return assemble_from_seed_snaps(
        p148_pres8=_pick("p148_pres8", "p148", nests=(pre,)),
        p160_pres8=_pick("p160_pres8", "p160", nests=(pre,)),
        p150=_pick("p150", nests=(s84,)),
        p158=_pick("p158", nests=(s88,)),
        p148_m8c=_pick("p148_m8c", "p148", nests=(s8c,)),
        p168_m8c=_pick("p168_m8c", "p168", nests=(s8c,)),
        k=k,
        tab=[_coerce_int(x, f"tab[{idx}]") for idx, x in enumerate(tab[:4])],
        f12=f12,
        lag=lag,
    )


def assemble_from_fill_gap(
    gap: bytes,
    k: int,
    tab: list[int],
    f12: int,
    *,
    lag: int = 1,
) -> bytes:
    """P2062 live 20B from mill gap at PRE-308090 / hid=310 (lag=1 last2)."""
    from qishen_pure._engine.medusa_field13_leaves import fill_m_from_gap

    m90, m8c, m88, m84 = fill_m_from_gap(gap)
    w0, w1, w2, w3 = w_from_fill_m_and_k(m90, m8c, m88, m84, k, tab)
    return assemble_from_w(w0, w1, w2, w3, f12, lag=lag)


def assemble_from_seed_gap(
    seed: bytes,
    gap: bytes,
    k: int,
    tab: list[int],
    f12: int,
    *,
    lag: int = 1,
) -> bytes:
    """derive_leaves(seed, gap, k, TAB): fill XOR, dest=10 mill-walk, or classic compose."""
    from qishen_pure._engine.medusa_field13_leaves import (
        fill_gap_ready,
        fill_m_from_d10_seed_gap,
        mill_d10_ready,
        snaps_from_seed_gap,
    )

    if fill_gap_ready(gap, k, tab):
        from qishen_pure._engine.medusa_field13_leaves import (
            fill_m_from_gap,
            fill_slots_hold_ser_w,
        )

        if fill_slots_hold_ser_w(seed, gap):
            m90, m8c, m88, m84 = fill_m_from_gap(gap)
            return assemble_from_w(m90, m8c, m88, m84, f12, lag=lag)
        return assemble_from_fill_gap(gap, k, tab, f12, lag=lag)
    if mill_d10_ready(gap, k):
        m90, m8c, m88, m84 = fill_m_from_d10_seed_gap(seed, gap, k)
        w0, w1, w2, w3 = w_from_fill_m_and_k(m90, m8c, m88, m84, k, tab)
        return assemble_from_w(w0, w1, w2, w3, f12, lag=lag)
    from qishen_pure._engine.medusa_field13_leaves import FILL_M90_GAP_OFF

    if len(gap) >= FILL_M90_GAP_OFF + 16:
        return assemble_from_fill_gap(gap, k, tab, f12, lag=lag)
    snaps = snaps_from_seed_gap(seed, gap, k=k)
    return assemble_from_seed_snaps(
        p148_pres8=snaps["p148_pres8"],
        p160_pres8=snaps["p160_pres8"],
        p150=snaps["p150"],
        p158=snaps["p158"],
        p148_m8c=snaps["p148_m8c"],
        p168_m8c=snaps["p168_m8c"],
        k=k,
        tab=tab,
        f12=f12,
        lag=lag,
    )


derive_leaves = assemble_from_seed_gap


def pack64_to_32(wide: bytes) -> bytes:
    """w2=62 pack: each 8B chunk bytes [1,3,5,6], reverse-chunk order. P2165 4/4."""
    if len(wide) < 64:
        raise ValueError("wide64 needs 64 bytes")
    out = bytearray(32)
    for i in range(8):
        c = wide[i * 8 : i * 8 + 8]
        j = 7 - i
        out[j * 4 : j * 4 + 4] = bytes((c[1], c[3], c[5], c[6]))
    return bytes(out)


def first16_from_wide(wide: bytes) -> bytes:
    ab = pack64_to_32(wide)
    return bytes(x ^ y for x, y in zip(ab[:16], ab[16:]))


def first16_from_ab32(ab: bytes) -> bytes:
    if len(ab) < 32:
        raise ValueError("need 32B A||B")
    return bytes(x ^ y for x, y in zip(ab[:16], ab[16:]))


def first16_from_ws(ws: bytes) -> bytes:
    """P2151: first16 = u32le(ws+136..152) xor u32le(ws+152..168)."""
    if len(ws) < 168:
        raise ValueError("mill-ws shorter than +168")
    a = struct.unpack_from("<IIII", ws, 136)
    b = struct.unpack_from("<IIII", ws, 152)
    return struct.pack("<IIII", *((x ^ y) & 0xFFFFFFFF for x, y in zip(a, b)))


def _coerce_hex_blob(value: Any, name: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("hex:"):
            return bytes.fromhex(text[4:])
        if text.startswith("base64:"):
            import base64

            return base64.b64decode(text[7:], validate=True)
        return bytes.fromhex(text)
    raise ValueError(f"{name} must be bytes or hex")


def field13_20b_from_first16(first16: bytes, url_ts: int, lag: int = 1) -> bytes:
    """Mill-less xor34-20B given first16 (P2208/P2227). last2 uses mill unix lag=1."""
    raw = bytes(first16)
    if len(raw) != 16:
        raise ValueError(f"first16 must contain exactly 16 bytes, got {len(raw)}")
    w0, w1, w2, w3 = struct.unpack("<4I", raw)
    return assemble_from_w(w0, w1, w2, w3, int(url_ts), lag=lag)


def assemble_from_wide64(wide: bytes, f12: int, *, lag: int = 1) -> bytes:
    """Mill-less 20B from w2=124 wide64 + url ts. first16 capture-free still OPEN."""
    w = first16_from_wide(wide)
    w0, w1, w2, w3 = struct.unpack("<IIII", w)
    return assemble_from_w(w0, w1, w2, w3, f12, lag=lag)


def assemble_from_w(
    w0: int, w1: int, w2: int, w3: int, f12: int, *, lag: int = 1
) -> bytes:
    v88 = u32le(w0) + u32le(w1)
    v90 = u32le(w2) + u32le(w3)
    first8 = v88.hex()
    mid8 = v90.hex()
    hi16 = pure_replay(mid8, "0" * 16, first8, OPS)
    last2 = compute_byte18_byte19(int(f12), lag=lag)
    out = bytes.fromhex(first8 + mid8 + hi16) + last2
    if len(out) != 20:
        raise RuntimeError(f"bad length {len(out)}")
    return out


def assemble_from_seed_snaps(
    *,
    p148_pres8: int,
    p160_pres8: int,
    p150: int,
    p158: int,
    p148_m8c: int,
    p168_m8c: int,
    k: int,
    tab: list[int],
    f12: int,
    lag: int = 1,
) -> bytes:
    m90, m8c, m88, m84 = m_from_seed_snaps(
        p148_pres8=p148_pres8,
        p160_pres8=p160_pres8,
        p150=p150,
        p158=p158,
        p148_m8c=p148_m8c,
        p168_m8c=p168_m8c,
        k=k,
    )
    w0, w1, w2, w3 = w_from_m_and_k(m90, m8c, m88, m84, k, tab)
    return assemble_from_w(w0, w1, w2, w3, f12, lag=lag)


__all__ = [
    "assemble_from_material_dict",
    "assemble_from_w",
    "assemble_from_wide64",
    "field13_20b_from_first16",
    "pack64_to_32",
    "first16_from_wide",
    "first16_from_ab32",
    "first16_from_ws",
    "assemble_from_fill_gap",
    "assemble_from_seed_gap",
    "derive_leaves",
    "assemble_from_seed_snaps",
    "w_from_m_and_k",
    "w_from_fill_m_and_k",
    "m_from_seed_snaps",
    "p150_h1_from_s6_ror22",
    "p168_h1_from_s9_ror26_s7",
    "s6_after_dest10_2dfdbc",
    "p160_h1_from_s8_s12",
    "p160_h1_from_s8_s6_s12",
    "s12_from_orn_s6_s0",
    "s11_from_eor_s6_2e0da8",
    "s6_e30_from_s6_s7_2dedec",
    "s11_d8_from_s8",
    "s7_h1_from_s10_s11_s8",
    "p150_from_s6_pres8",
    "p150_from_prior_p168_pres8",
    "p150_prior_from_h69_s23",
    "p168_mid_from_h69_s11",
    "p168_final_from_s5_s8_s10",
    "p168_final_from_pres8_s10",
    "s7_post_e30_from_pre",
    "s10_mid_from_s7_post",
    "s10_mid_from_s7_pre_s6",
    "s10_mid_from_p158_h69",
    "k_from_ts",
    "rol32",
    "ror32",
    "OPS",
    "TAB_OFF",
    "TAB_LIVE",
    "TBL_LIVE",
    "C_PRE",
    "C_S10",
    "C_S9",
    "S5_PRIOR_FINAL",
    "LEAF_BOARD_20260812",
]

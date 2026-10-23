"""WRAP mill src16 from intern64. Live-locked pid 5294 SETB[:16]."""
from __future__ import annotations

import json
import struct
from pathlib import Path

from .wrap_lanusk import LANUSK_MD5_12, TAB_B, src16_from_mill_rf, word0_from_chain

ROOT = Path(__file__).resolve().parent
SLIM = ROOT / "_wrap_mill_slim.json"

MILL1 = 0x1000
MILL8 = 0x2000
INTERN = 0x3000

_OPS: dict[int, tuple[int, int]] | None = None


def u32(x: int) -> int:
    return int(x) & 0xFFFFFFFF


def ror(x: int, n: int) -> int:
    x = u32(x)
    n &= 31
    return u32((x >> n) | (x << (32 - n)))


def intern48_from_intern32(intern32: bytes, intern16: bytes | None = None) -> bytes:
    """intern mill intern48 = last intern32 blob || intern-node intern16.

    intern16 is often 16×0. Live:
      intern32 395593d7… || intern16 840e4358… mills SETB[:16] 307d8a29….
      intern32 5c9de9ad… || 16×0 mills SETB[:16] 293e49a2….
    intern32 is session getrandom nonce, not query md5/sha/sm3.
    """
    raw32 = bytes(intern32)
    if len(raw32) != 32:
        raise ValueError("intern32 must be 32B")
    raw16 = bytes(intern16) if intern16 is not None else b"\x00" * 16
    if len(raw16) != 16:
        raise ValueError("intern16 must be 16B")
    return raw32 + raw16


def intern64_from_intern48(intern48: bytes) -> bytes:
    raw = bytes(intern48)
    if len(raw) != 48:
        raise ValueError("intern48 must be 48B")
    return raw + LANUSK_MD5_12 + struct.pack("<I", 0x180)


def _ops() -> dict[int, tuple[int, int]]:
    global _OPS
    if _OPS is None:
        rows = json.loads(SLIM.read_text(encoding="utf-8"))
        _OPS = {int(pc): (int(hid), int(word)) for pc, hid, word in rows}
    return _OPS


def _locate(mem: dict[int, bytearray], ptr: int, off: int, n: int):
    addr = (int(ptr) + int(off)) & 0xFFFFFFFFFFFFFFFF
    blob = mem.get(int(ptr) & 0xFFFFFFFFFFFFFFFF)
    base = int(ptr) & 0xFFFFFFFFFFFFFFFF
    if blob is None:
        for b, raw in mem.items():
            if b <= addr < b + max(len(raw), 1):
                blob, base = raw, b
                break
    if blob is None:
        return None
    i = addr - base
    if i < 0:
        return None
    if i + n > len(blob):
        blob.extend(b"\x00" * (i + n - len(blob)))
    return blob, i


def _s32(mem, ptr, off) -> int:
    loc = _locate(mem, ptr, off, 4)
    if loc is None:
        return 0
    blob, i = loc
    return int.from_bytes(blob[i : i + 4], "little", signed=True) & 0xFFFFFFFF


def _u64(mem, ptr, off) -> int:
    loc = _locate(mem, ptr, off, 8)
    if loc is None:
        return 0
    blob, i = loc
    return int.from_bytes(blob[i : i + 8], "little")


def _store(mem, ptr, off, val, n) -> None:
    base = int(ptr) & 0xFFFFFFFFFFFFFFFF
    if base not in mem:
        mem[base] = bytearray(256)
    loc = _locate(mem, ptr, off, n)
    if loc is None:
        return
    blob, i = loc
    blob[i : i + n] = (int(val) & ((1 << (8 * n)) - 1)).to_bytes(n, "little")


def _step(rf, intern, intern_addr, mem, hid, word, pc) -> int | None:
    b0 = word & 0xFF
    b1 = (word >> 8) & 0xFF
    b2 = (word >> 16) & 0xFF
    off = struct.unpack("<h", struct.pack("<H", word >> 16 & 0xFFFF))[0]

    def R(i):
        return rf[i]

    def W(i, v):
        rf[i] = u32(v)

    def Wp(i, v):
        rf[i] = int(v) & 0xFFFFFFFFFFFFFFFF

    if hid == 38:
        W(b2, u32(R(b1) + R(b0)))
    elif hid == 181:
        W(b2, R(b1) ^ R(b0))
    elif hid == 8:
        W(b2, R(b1) | R(b0))
    elif hid == 11:
        W(b2, R(b1) & R(b0))
    elif hid == 10:
        W(b1, u32(R(b0) << (b2 & 31)))
    elif hid == 30:
        W(b1, u32(R(b0)) >> (b2 & 31))
    elif hid == 109:
        W(b1, ror(R(b0), b2))
    elif hid == 42:
        W(b2, u32(~(R(b1) | R(b0))))
    elif hid == 55:
        Wp(b2, R(b0))
    elif hid == 12:
        W(b1, u32((off & 0xFFFF) << 16))
    elif hid == 102:
        W(b1, R(b0) | (off & 0xFFFF))
    elif hid == 112:
        W(b1, R(b0) & (off & 0xFFFF))
    elif hid == 139:
        W(b1, off)
    elif hid == 105:
        W(b1, u32(R(b0) + off))
    elif hid == 123:
        if R(b0) == intern_addr:
            W(b1, intern[off] if 0 <= off < len(intern) else 0)
        else:
            W(b1, _s32(mem, R(b0), off) & 0xFF)
    elif hid == 76:
        W(b1, _s32(mem, R(b0), off))
    elif hid == 73:
        Wp(b1, R(b0) + off)
    elif hid == 50:
        _store(mem, R(b0), off, R(b1), 8)
    elif hid == 167:
        _store(mem, R(b0), off, R(b1), 4)
    elif hid == 1:
        Wp(b1, _u64(mem, R(b0), off))
    if hid == 189:
        return None
    return pc + 1


def _mill_rf(intern64: bytes) -> dict[str, int]:
    intern = bytes(intern64)[:64]
    if len(intern) < 64:
        intern += b"\x00" * (64 - len(intern))
    ops = _ops()
    mill8 = bytearray(32)
    mill8[0:8] = (0x40).to_bytes(8, "little")
    mill8[8:12] = TAB_B[0].to_bytes(4, "little")
    mill8[12:16] = TAB_B[1].to_bytes(4, "little")
    mill8[16:20] = TAB_B[2].to_bytes(4, "little")
    mill8[20:24] = TAB_B[3].to_bytes(4, "little")
    mill1 = bytearray(128)
    mill1[8:12] = TAB_B[0].to_bytes(4, "little")
    mill1[12:16] = TAB_B[3].to_bytes(4, "little")
    mill1[24:28] = TAB_B[1].to_bytes(4, "little")
    mill1[28:32] = TAB_B[2].to_bytes(4, "little")
    mem = {MILL1: mill1, MILL8: mill8, INTERN: bytearray(intern)}
    rf = [0] * 32
    rf[1] = MILL1
    rf[3] = 0x32
    rf[4] = MILL1 + 0x70
    rf[5] = 0x3C
    rf[6] = MILL8 + 0x54
    rf[7] = 0x400000000
    rf[8] = MILL8
    rf[9] = INTERN
    rf[10] = 4
    rf[20] = 4
    rf[21] = MILL8 - 0x30
    rf[22] = MILL8
    rf[23] = 4
    rf[24] = INTERN
    out: dict[str, int] = {}
    pc = 4
    n = 0
    while pc in ops and pc <= 1014 and n < 8000:
        hid, word = ops[pc]
        if pc in (973, 978, 1003, 1013) and str(pc) not in out:
            out[str(pc)] = None
            for k in (5, 6, 7, 8, 9):
                out[f"{pc}_{k}"] = u32(rf[k])
        nxt = _step(rf, intern, INTERN, mem, hid, word, pc)
        if nxt is None:
            break
        pc = nxt
        n += 1
    return out


def src16_from_intern64(intern64: bytes) -> bytes:
    """intern64 = intern48 || LANUSK_MD5_12 || u32 0x180."""
    st = _mill_rf(intern64)
    rf5_973 = st["973_5"]
    rf6_973 = st["973_6"]
    w0 = word0_from_chain(rf5_973, rf6_973)
    rf5_w0 = (w0 - TAB_B[0]) & 0xFFFFFFFF
    rf5_w2 = st["1003_5"]
    rf6_w3 = st["1003_6"]
    w1_add = (st["1013_5"] + st["1013_7"]) & 0xFFFFFFFF
    return src16_from_mill_rf(rf5_w0, rf5_w2, rf6_w3, w1_add)


__all__ = [
    "intern48_from_intern32",
    "intern64_from_intern48",
    "src16_from_intern64",
]

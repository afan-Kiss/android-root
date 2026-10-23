"""Compact WRAP f18 assemble: TAB_A/TAB_B + last4 mill (pid 18854 / 5294)."""
from __future__ import annotations

import struct

# SO+0xc3040 TAB_A. f18 XOR key is TAB_A[0]; word1 ^= TAB_A[1] at 0x308090.
TAB_A = (0x19BE4866, 0xE85986B4, 0xE19B326E, 0x71D1D7D4)
# SO+0xc3090 TAB_B. Copied into mill session RF[1] at +8/+24/+28/+12.
TAB_B = (0x79E0F2FB, 0xC8B52570, 0xEBC2F8CD, 0x7C104D93)
LANUSK_XOR_KEY = TAB_A[0]
LANUSK_LAST4_XOR0 = 0x20
RF1_TAB_B0 = TAB_B[0]
# SO+0xea9e0 mill const pool. RF[29]=+0x10, RF[17]=+0x1c, then lanusk n=12 MD5 suffix.
MILL_K29 = 0xFAEA73C1
MILL_K17 = 0x2D59351D
LANUSK_MD5_12 = bytes.fromhex("8496779dd4150bf8db6dbcb6")
LAST4_SEED = 0x20220420
LAST4_LOOP = 12


def _u32(value: int) -> int:
    return int(value) & 0xFFFFFFFF


def ror32(value: int, n: int) -> int:
    x = int(value) & 0xFFFFFFFF
    k = int(n) & 31
    return ((x >> k) | (x << (32 - k))) & 0xFFFFFFFF


def last4_from_dest16(dest16: bytes) -> bytes:
    """Nested last4 mill pc0-37. 纯算 from dest16 (session+0x5fe0 first 16B)."""
    raw = bytes(dest16)
    if len(raw) != 16:
        raise ValueError("last4 dest16 must be 16B")
    rf5 = 0
    rf6 = 0
    rf8 = LAST4_SEED
    rf10 = 0
    idx = 0
    while rf6 != LAST4_LOOP:
        rf5 = rf6 & 1
        if rf5 == 0:
            rf5 = _u32(rf8 << 7)
            rf5 = _u32(rf8 ^ rf5)
            rf8 = _u32(rf8) >> 3
            rf5 = _u32(rf8 ^ rf5)
            rf8 = _u32(raw[idx] ^ rf5)
        else:
            rf5 = raw[idx]
            rf10 = _u32(rf8 << 11)
            rf5 = _u32(rf5 | rf10)
            rf10 = _u32(rf8) >> 5
            rf8 = _u32(rf10 ^ rf8)
            rf5 = _u32(rf5 ^ rf8)
            rf8 = _u32(~rf5)
        rf6 = _u32(rf6 + 1)
        idx += 1
    return struct.pack("<I", _u32(rf8))


def assemble_lanusk_hash(
    src16: bytes,
    xor_key: int = LANUSK_XOR_KEY,
    last4: bytes | None = None,
) -> bytes:
    """Compact WRAP f18 20B.

    dest[0:4] = word0 ^ TAB_A[0]; dest[4:16]=src16[4:]; last4; [16]^=0x20 [19]^=1.
    last4 default = last4_from_dest16(dest[:16]).
    """
    src = bytes(src16)
    if len(src) != 16:
        raise ValueError("lanusk src16 must be 16B")
    head = struct.pack("<I", (struct.unpack_from("<I", src, 0)[0] ^ (int(xor_key) & 0xFFFFFFFF)))
    dest16 = head + src[4:]
    if last4 is None:
        tail = last4_from_dest16(dest16)
    else:
        tail = bytes(last4)
        if len(tail) != 4:
            raise ValueError("lanusk last4 must be 4B")
    out = bytearray(dest16 + tail)
    out[16] ^= LANUSK_LAST4_XOR0
    out[19] ^= 1
    return bytes(out)


def src16_w2_w3_from_rf1(rf1: bytes, rf5: int, rf6: int) -> tuple[int, int]:
    raw = bytes(rf1)
    if len(raw) < 32:
        raise ValueError("rf1 blob must be >=32B")
    w2 = (struct.unpack_from("<I", raw, 28)[0] + (int(rf5) & 0xFFFFFFFF)) & 0xFFFFFFFF
    w3 = (struct.unpack_from("<I", raw, 12)[0] + (int(rf6) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return w2, w3


def rf1_tab_b_words(rf1: bytes) -> tuple[int, int, int, int]:
    raw = bytes(rf1)
    if len(raw) < 32:
        raise ValueError("rf1 blob must be >=32B")
    return (
        struct.unpack_from("<I", raw, 8)[0],
        struct.unpack_from("<I", raw, 12)[0],
        struct.unpack_from("<I", raw, 24)[0],
        struct.unpack_from("<I", raw, 28)[0],
    )


def word0_from_chain(rf5_973: int, rf6: int) -> int:
    mixed = (ror32(int(rf5_973) + MILL_K29, 26) + int(rf6)) & 0xFFFFFFFF
    return (mixed + TAB_B[0]) & 0xFFFFFFFF


def word1_from_chain(rf5: int, rf6: int, rf9: int, rf7: int) -> int:
    hid282 = ror32((int(rf5) ^ int(rf6)) + int(rf9) + MILL_K17, 11)
    return ((hid282 + int(rf7)) ^ TAB_A[1]) & 0xFFFFFFFF


def src16_from_mill_rf(rf5_w0: int, rf5_w2: int, rf6: int, w1_add: int) -> bytes:
    w0 = (int(rf5_w0) + TAB_B[0]) & 0xFFFFFFFF
    w1 = (int(w1_add) ^ TAB_A[1]) & 0xFFFFFFFF
    w2 = ((TAB_B[2] + int(rf5_w2)) ^ TAB_A[2]) & 0xFFFFFFFF
    w3 = ((TAB_B[3] + int(rf6)) ^ TAB_A[3]) & 0xFFFFFFFF
    return struct.pack("<IIII", w0, w1, w2, w3)


__all__ = [
    "LANUSK_LAST4_XOR0",
    "LANUSK_MD5_12",
    "LANUSK_XOR_KEY",
    "LAST4_LOOP",
    "LAST4_SEED",
    "MILL_K17",
    "MILL_K29",
    "RF1_TAB_B0",
    "TAB_A",
    "TAB_B",
    "assemble_lanusk_hash",
    "last4_from_dest16",
    "rf1_tab_b_words",
    "ror32",
    "src16_from_mill_rf",
    "src16_w2_w3_from_rf1",
    "word0_from_chain",
    "word1_from_chain",
]

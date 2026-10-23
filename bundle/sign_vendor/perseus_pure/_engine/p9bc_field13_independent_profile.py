#!/usr/bin/env python3
"""Independent byte-exact lift of the v39 field13 selector-2 child VM profile.

This module is intentionally separate from ``p9bc_scatter_e_profile``.  The
profile was recovered from the field13 ``0x40d342c0`` execution path and is
validated against both field13 full-trace runs.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KEY_TABLE = ROOT / "perseus_payload_scatter_key_schedule_table.bin"
TABLE_ANCHOR = 0x411
TABLE_SIZE = 0x100
BLOCK_SIZE = 16

PREVIOUS_KEY = bytes.fromhex("ad725cb23141db17fce838fe45734fe8")
EXPANDED_KEY = bytes.fromhex("71cdfce7408c27f0bc641f0ef91750e6")
MIDDLE_XOR_MASK = bytes.fromhex("a5494534296eb5744d71bbc85a215d31")
FIXED_IV = bytes.fromhex("64d3d55e4e03aaa6489f882e7156448f")

# VM phase at program words 0x40d14698..0x40d14750 and
# 0x40d14a30..0x40d14aa0.  This differs at lanes 7/11/15 from the old
# scatter SIGMA lift and is the reason that old selector-2 input->F failed.
CHILD_PHASE_PERMUTATION = (
    0, 9, 14, 11,
    4, 13, 2, 15,
    8, 1, 6, 3,
    12, 5, 10, 7,
)

# Final S-box store phase at 0x40d14a30..0x40d14aa0.
FINAL_STORE_PERMUTATION = (
    4, 13, 2, 15,
    8, 1, 6, 3,
    12, 5, 10, 7,
    0, 9, 14, 11,
)


@dataclass(frozen=True)
class BlockTrace:
    block_input: bytes
    initial_key_layout: bytes
    after_initial_xor: bytes
    after_first_substitution: bytes
    after_word_cycle: bytes
    after_child_phase_permutation: bytes
    after_mix: bytes
    expanded_key_layout: bytes
    pre_final_state: bytes
    after_final_substitution: bytes
    F: bytes
    G: bytes
    output: bytes


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def rotate_each_word_left_one(value: bytes) -> bytes:
    """Apply the VM byte layout ``[b1,b2,b3,b0]`` to every 4-byte word."""
    if len(value) % 4:
        raise ValueError("word rotation input length must be divisible by four")
    return b"".join(value[i + 1 : i + 4] + value[i : i + 1] for i in range(0, len(value), 4))


def cycle_four_words_left(value: bytes) -> bytes:
    """Apply the actual 16-byte word cycle ``W1||W2||W3||W0``."""
    if len(value) != BLOCK_SIZE:
        raise ValueError("word cycle requires one 16-byte block")
    return value[4:] + value[:4]


def permute(value: bytes, permutation: tuple[int, ...]) -> bytes:
    if len(value) != len(permutation):
        raise ValueError("permutation width mismatch")
    return bytes(value[index] for index in permutation)


def xtime(value: int) -> int:
    return (((value << 1) ^ 0x11B) & 0xFF) if value & 0x80 else value << 1


def mix_rows(value: bytes) -> bytes:
    """Lift of the four repeated ``0x40d35700`` child-VM column windows."""
    if len(value) != BLOCK_SIZE:
        raise ValueError("mix_rows requires one 16-byte block")
    output = bytearray(BLOCK_SIZE)
    for column in range(4):
        a, b, c, d = (value[column + 4 * row] for row in range(4))
        mixed = (
            xtime(a) ^ xtime(b) ^ b ^ c ^ d,
            a ^ xtime(b) ^ xtime(c) ^ c ^ d,
            a ^ b ^ xtime(c) ^ xtime(d) ^ d,
            xtime(a) ^ a ^ b ^ c ^ xtime(d),
        )
        for row, byte in enumerate(mixed):
            output[column + 4 * row] = byte
    return bytes(output)


def load_sbox(path: Path = KEY_TABLE) -> bytes:
    table = path.read_bytes()
    page = table[TABLE_ANCHOR : TABLE_ANCHOR + TABLE_SIZE]
    if len(page) != TABLE_SIZE:
        raise ValueError("selector-2 runtime S-box page is incomplete")
    return page


def trace_block(block: bytes, sbox: bytes | None = None) -> BlockTrace:
    if len(block) != BLOCK_SIZE:
        raise ValueError("field13 child profile requires one 16-byte block")
    if sbox is None:
        sbox = load_sbox()
    if len(sbox) != TABLE_SIZE:
        raise ValueError("field13 child profile S-box must contain 256 bytes")

    initial_key_layout = rotate_each_word_left_one(PREVIOUS_KEY)
    after_initial_xor = xor_bytes(block, initial_key_layout)
    after_first_substitution = bytes(sbox[value] for value in after_initial_xor)
    after_word_cycle = cycle_four_words_left(after_first_substitution)
    after_child_phase_permutation = permute(after_word_cycle, CHILD_PHASE_PERMUTATION)
    after_mix = rotate_each_word_left_one(mix_rows(after_child_phase_permutation))
    expanded_key_layout = rotate_each_word_left_one(EXPANDED_KEY)
    pre_final_state = xor_bytes(after_mix, expanded_key_layout)
    after_final_substitution = bytes(sbox[value] for value in pre_final_state)
    f_state = permute(after_final_substitution, FINAL_STORE_PERMUTATION)
    g_state = xor_bytes(f_state, MIDDLE_XOR_MASK)
    output = xor_bytes(g_state, EXPANDED_KEY)
    return BlockTrace(
        block_input=block,
        initial_key_layout=initial_key_layout,
        after_initial_xor=after_initial_xor,
        after_first_substitution=after_first_substitution,
        after_word_cycle=after_word_cycle,
        after_child_phase_permutation=after_child_phase_permutation,
        after_mix=after_mix,
        expanded_key_layout=expanded_key_layout,
        pre_final_state=pre_final_state,
        after_final_substitution=after_final_substitution,
        F=f_state,
        G=g_state,
        output=output,
    )


def encrypt_block(block: bytes, sbox: bytes | None = None) -> bytes:
    return trace_block(block, sbox).output


def pkcs7_pad(source: bytes) -> bytes:
    padding = BLOCK_SIZE - (len(source) % BLOCK_SIZE)
    return source + bytes([padding]) * padding


def generate_source32(source19: bytes, sbox: bytes | None = None) -> bytes:
    if len(source19) != 19:
        raise ValueError("field13 source material must contain exactly 19 bytes")
    padded = pkcs7_pad(source19)
    if len(padded) != 32:
        raise AssertionError("19-byte PKCS#7 input must produce 32 bytes")
    c0_input = xor_bytes(padded[:16], FIXED_IV)
    c0 = encrypt_block(c0_input, sbox)
    c1_input = xor_bytes(padded[16:], c0)
    c1 = encrypt_block(c1_input, sbox)
    return c0 + c1


def generate_field13(source19: bytes, sbox: bytes | None = None) -> bytes:
    return generate_source32(source19, sbox)[19:32]


__all__ = [
    "BLOCK_SIZE",
    "CHILD_PHASE_PERMUTATION",
    "EXPANDED_KEY",
    "FINAL_STORE_PERMUTATION",
    "FIXED_IV",
    "MIDDLE_XOR_MASK",
    "PREVIOUS_KEY",
    "TABLE_ANCHOR",
    "BlockTrace",
    "cycle_four_words_left",
    "encrypt_block",
    "generate_field13",
    "generate_source32",
    "load_sbox",
    "mix_rows",
    "permute",
    "rotate_each_word_left_one",
    "trace_block",
    "xor_bytes",
]

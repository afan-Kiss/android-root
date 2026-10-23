#!/usr/bin/env python3
"""Pure-Python selector-bound scatter E_profile and two-block CBC source19.

All four selector profiles are statically exported from the prebuilt child
programs.  Field13 is intentionally not routed through this module: it shares
only PKCS#7/CBC framing and uses a distinct block profile.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent
KEY_TABLE = ROOT / "perseus_payload_scatter_key_schedule_table.bin"
BLOCK_SIZE = 16
SOURCE_LENGTH = 19
IV = bytes.fromhex("64d3d55e4e03aaa6489f882e7156448f")
BASE_KEY_STATE = bytes.fromhex("d61ad2474a2955e28780b60b3e1bc11d")

F_STAGE_PERMUTATIONS = {
    0: (12, 9, 14, 3, 4, 13, 6, 7, 0, 5, 2, 11, 8, 1, 10, 15),
    1: (4, 9, 14, 11, 0, 13, 6, 3, 8, 5, 2, 15, 12, 1, 10, 7),
    2: (4, 13, 2, 15, 8, 1, 6, 3, 12, 5, 10, 7, 0, 9, 14, 11),
    3: (8, 13, 2, 15, 4, 1, 6, 3, 12, 5, 10, 11, 0, 9, 14, 7),
}

PROFILE_CONFIG = {
    0: {"constant": "cb615ffa", "anchor": 529, "lane_order": (1, 2, 3, 0)},
    1: {"constant": "85660dff", "anchor": 785, "lane_order": (1, 0, 2, 3)},
    2: {"constant": "7b688ef5", "anchor": 1041, "lane_order": (3, 0, 1, 2)},
    3: {"constant": "4c08bff6", "anchor": 1297, "lane_order": (0, 3, 1, 2)},
}

STATIC_MIDDLE_KEYS = {
    0: bytes.fromhex("51f2bb5c2fe8be72a0be5ab5c81dc4ec"),
    1: bytes.fromhex("0eb745214581695de8b5fed5383aa5bf"),
    2: bytes.fromhex("a5494534296eb5744d71bbc85a215d31"),
    3: bytes.fromhex("faf008562aa7d4af31f9f5de58d93fbc"),
}


class EProfileInputMissing(ValueError):
    """Raised only when a required request/profile input is actually absent."""


@dataclass(frozen=True)
class EProfile:
    selector: int
    anchor: int
    constant: bytes
    lane_order: tuple[int, int, int, int]
    previous_key: bytes
    expanded_key: bytes
    middle_key: bytes
    sbox: bytes


def xor(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def _expand_round(previous_key: bytes, sbox: bytes, rcon: int) -> bytes:
    if len(previous_key) != 16 or len(sbox) != 256:
        raise ValueError("invalid E_profile key-expansion input")
    w3 = previous_key[12:16]
    transform = bytes((sbox[w3[1]] ^ rcon, sbox[w3[2]], sbox[w3[3]], sbox[w3[0]]))
    words = [previous_key[i:i + 4] for i in range(0, 16, 4)]
    out = [xor(words[0], transform)]
    for word in words[1:]:
        out.append(xor(word, out[-1]))
    return b"".join(out)


def _scatter_lanes(state: bytes, lane_order: tuple[int, int, int, int]) -> bytes:
    if len(state) != 16 or sorted(lane_order) != [0, 1, 2, 3]:
        raise ValueError("invalid lane-scatter input")
    out = bytearray(16)
    for word in range(0, 16, 4):
        for canonical_lane, destination_lane in enumerate(lane_order):
            out[word + destination_lane] = state[word + canonical_lane]
    return bytes(out)


def derive_profile_from_key(
    selector: int, base_key: bytes, key_table: bytes | None = None
) -> EProfile:
    """Build a selector profile from an arbitrary 16-byte slot key.

    Scatter / field13 use BASE_KEY_STATE.  Mill-less Medusa WRAP uses the
    v34 AES key in the same slot and the same selector-2 child program.
    """
    if len(base_key) != BLOCK_SIZE:
        raise ValueError("E_profile base key must contain 16 bytes")
    try:
        config = PROFILE_CONFIG[selector]
        permutation = F_STAGE_PERMUTATIONS[selector]
    except KeyError as exc:
        raise EProfileInputMissing(f"scatter selector must be 0..3, got {selector}") from exc
    if sorted(permutation) != list(range(16)):
        raise ValueError(f"selector {selector} F-stage map is not a permutation")
    table = KEY_TABLE.read_bytes() if key_table is None else key_table
    anchor = config["anchor"]
    sbox = table[anchor:anchor + 256]
    if len(sbox) != 256:
        raise EProfileInputMissing(f"key table does not cover selector {selector} S-box")
    constant = bytes.fromhex(config["constant"])
    previous = bytes(v ^ constant[i & 3] for i, v in enumerate(base_key))
    expanded = _expand_round(previous, sbox, constant[1])
    canonical_round2 = _expand_round(expanded, sbox, constant[2])
    middle = _scatter_lanes(canonical_round2, config["lane_order"])
    return EProfile(selector, anchor, constant, config["lane_order"], previous, expanded, middle, sbox)


def derive_profile(selector: int, key_table: bytes | None = None) -> EProfile:
    profile = derive_profile_from_key(selector, BASE_KEY_STATE, key_table)
    expected = STATIC_MIDDLE_KEYS[selector]
    if profile.middle_key != expected:
        raise ValueError(f"selector {selector} static middle-key derivation mismatch")
    return profile


def load_profile(selector: int) -> EProfile:
    return derive_profile(selector)


# Legacy comparison helpers retained for historical analyzers only.
def q(state: bytes) -> bytes:
    if len(state) != 16:
        raise ValueError("q state must contain 16 bytes")
    return b"".join(bytes((state[i + 1], state[i], state[i + 2], state[i + 3])) for i in range(0, 16, 4))

def pi(state: bytes) -> bytes:
    if len(state) != 16:
        raise ValueError("pi state must contain 16 bytes")
    return state[4:8] + state[:4] + state[8:]

def sigma(state: bytes) -> bytes:
    if len(state) != 16:
        raise ValueError("sigma state must contain 16 bytes")
    indices = (0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3)
    return bytes(state[index] for index in indices)


def xtime(value: int) -> int:
    return ((value << 1) ^ 0x11B) & 0xFF if value & 0x80 else value << 1


def mix_rows(state: bytes) -> bytes:
    if len(state) != 16:
        raise ValueError("MixRows state must contain 16 bytes")
    out = bytearray(16)
    for column in range(4):
        a, b, c, d = (state[column + 4 * row] for row in range(4))
        mixed = (
            xtime(a) ^ xtime(b) ^ b ^ c ^ d,
            a ^ xtime(b) ^ xtime(c) ^ c ^ d,
            a ^ b ^ xtime(c) ^ xtime(d) ^ d,
            xtime(a) ^ a ^ b ^ c ^ xtime(d),
        )
        for row, value in enumerate(mixed):
            out[column + 4 * row] = value
    return bytes(out)


def _substitute_and_permute(state: bytes, profile: EProfile) -> bytes:
    substituted = bytes(profile.sbox[value] for value in state)
    permutation = F_STAGE_PERMUTATIONS[profile.selector]
    return bytes(substituted[source] for source in permutation)


def first_middle_state(block: bytes, profile: EProfile) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("E_profile block must contain 16 bytes")
    state = xor(block, _scatter_lanes(profile.previous_key, profile.lane_order))
    state = _substitute_and_permute(state, profile)
    state = _scatter_lanes(mix_rows(state), profile.lane_order)
    return xor(state, _scatter_lanes(profile.expanded_key, profile.lane_order))


def f_stage_from_middle(middle_state: bytes, profile: EProfile) -> bytes:
    if len(middle_state) != BLOCK_SIZE:
        raise ValueError("E_profile middle state must contain 16 bytes")
    return _substitute_and_permute(middle_state, profile)


def second_precommit_state(block: bytes, profile: EProfile) -> bytes:
    return f_stage_from_middle(first_middle_state(block, profile), profile)


def middle_transform(state: bytes, profile: EProfile) -> bytes:
    if len(state) != BLOCK_SIZE:
        raise ValueError("E_profile F state must contain 16 bytes")
    return xor(state, profile.middle_key)


def encrypt_block(block: bytes, profile: EProfile) -> bytes:
    """Encrypt one already-CBC-xored block with a complete selector profile."""
    f_state = second_precommit_state(block, profile)
    g_state = middle_transform(f_state, profile)
    return xor(g_state, profile.expanded_key)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("invalid PKCS#7 block size")
    count = block_size - len(data) % block_size
    return data + bytes((count,)) * count


def encrypt_source32(raw_seed: bytes, selector: int, iv: bytes = IV) -> bytes:
    """Return C0||C1 for one 19-byte scatter raw seed."""
    if len(raw_seed) != SOURCE_LENGTH:
        raise EProfileInputMissing(f"scatter raw_seed must contain 19 bytes, got {len(raw_seed)}")
    if len(iv) != BLOCK_SIZE:
        raise EProfileInputMissing("scatter CBC IV must contain 16 bytes")
    profile = load_profile(selector)
    padded = pkcs7_pad(raw_seed)
    if len(padded) != 32:
        raise ValueError("19-byte scatter seed must pad to exactly two blocks")
    block0 = xor(padded[:16], iv)
    cipher0 = encrypt_block(block0, profile)
    block1 = xor(padded[16:32], cipher0)
    cipher1 = encrypt_block(block1, profile)
    return cipher0 + cipher1


def generate_source19(raw_seed: bytes, selector: int, iv: bytes = IV) -> bytes:
    return encrypt_source32(raw_seed, selector, iv)[:SOURCE_LENGTH]


def field13_vectors() -> list[dict[str, object]]:
    """Comparison-only vectors; field13 does not use this scatter E_profile."""
    report = json.loads((ROOT / "p9bc_field13_source32_static_upstream_report.json").read_text(encoding="utf-8"))
    result = []
    for run, vector in report["runs"].items():
        padded = bytes.fromhex(vector["input19"]) + b"\x0d" * 13
        ciphertext = bytes.fromhex(vector["committed_source32"])
        p0 = xor(padded[:16], bytes.fromhex(vector["iv16"]))
        p1 = xor(padded[16:], ciphertext[:16])
        result.extend((
            {"origin": f"field13_run_{run}", "block": 0, "input": p0.hex(), "output": ciphertext[:16].hex()},
            {"origin": f"field13_run_{run}", "block": 1, "input": p1.hex(), "output": ciphertext[16:].hex()},
        ))
    return result


# Backward-compatible names used by earlier analysis scripts.
MIDDLE_KEYS = STATIC_MIDDLE_KEYS
PROFILES = PROFILE_CONFIG

__all__ = [
    "BASE_KEY_STATE", "BLOCK_SIZE", "EProfile", "EProfileInputMissing",
    "F_STAGE_PERMUTATIONS", "IV", "MIDDLE_KEYS", "PROFILE_CONFIG",
    "SOURCE_LENGTH", "STATIC_MIDDLE_KEYS", "derive_profile",
    "derive_profile_from_key", "encrypt_block",
    "encrypt_source32", "f_stage_from_middle", "field13_vectors",
    "first_middle_state", "generate_source19", "load_profile", "middle_transform",
    "mix_rows", "pi", "pkcs7_pad", "q", "second_precommit_state", "sigma", "xor",
]

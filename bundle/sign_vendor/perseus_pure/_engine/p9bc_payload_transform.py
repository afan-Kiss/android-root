"""Replay the confirmed v39 X-Perseus payload transform."""
from __future__ import annotations

from dataclasses import dataclass

from .extra import get_key_hash
from .medusaEncrypt import V39_MASK_BIT_ORDER, V39_SIGN_KEY, inv_xmxor, xmxor


SCATTER_BYTE_COUNT = 19
SCATTER_BIT_COUNT = SCATTER_BYTE_COUNT * 8
SCATTER_OUTPUT_OFFSET = 1


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint value must be non-negative")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def build_payload_plaintext(protobuf_chunk: bytes, json_chunk: bytes) -> bytes:
    """Build fields 1, 3, and 4 of the pre-transform payload envelope."""
    return (
        b"\x08\x01"
        + b"\x1a" + encode_varint(len(protobuf_chunk)) + protobuf_chunk
        + b"\x22" + encode_varint(len(json_chunk)) + json_chunk
    )


def _payload_key(transform_random: int, sign_key: bytes) -> bytes:
    key, _ = get_key_hash(sign_key, transform_random)
    return bytes(key)


def apply_scatter(data: bytes, scatter_mask: bytes) -> bytes:
    if len(scatter_mask) != SCATTER_BYTE_COUNT:
        raise ValueError(f"scatter mask must contain {SCATTER_BYTE_COUNT} bytes")
    if len(data) < SCATTER_OUTPUT_OFFSET + SCATTER_BIT_COUNT:
        raise ValueError("payload is too short for the v39 scatter region")
    output = bytearray(data)
    for bit_index in range(SCATTER_BIT_COUNT):
        if (scatter_mask[bit_index >> 3] >> (bit_index & 7)) & 1:
            output[SCATTER_OUTPUT_OFFSET + bit_index] ^= (
                1 << V39_MASK_BIT_ORDER[bit_index & 7]
            )
    return bytes(output)


def transform_payload(
    plaintext: bytes,
    transform_random: int,
    scatter_mask: bytes,
    sign_key: bytes = V39_SIGN_KEY,
) -> bytes:
    key = _payload_key(transform_random, sign_key)
    transformed = bytes(xmxor(bytearray(plaintext), bytearray(key)))
    return apply_scatter(transformed, scatter_mask)


def recover_payload(
    ciphertext: bytes,
    transform_random: int,
    scatter_mask: bytes,
    sign_key: bytes = V39_SIGN_KEY,
) -> bytes:
    key = _payload_key(transform_random, sign_key)
    unscattered = apply_scatter(ciphertext, scatter_mask)
    return bytes(inv_xmxor(bytearray(unscattered), bytearray(key)))


def recover_scatter_mask(
    plaintext: bytes,
    ciphertext: bytes,
    transform_random: int,
    sign_key: bytes = V39_SIGN_KEY,
) -> bytes:
    """Recover the 19-byte mask from a known plaintext/ciphertext pair."""
    if len(plaintext) != len(ciphertext):
        raise ValueError("plaintext and ciphertext lengths differ")
    key = _payload_key(transform_random, sign_key)
    base = bytes(xmxor(bytearray(plaintext), bytearray(key)))
    difference = bytes(left ^ right for left, right in zip(base, ciphertext))
    mask = bytearray(SCATTER_BYTE_COUNT)
    scatter_end = SCATTER_OUTPUT_OFFSET + SCATTER_BIT_COUNT
    for output_index, value in enumerate(difference):
        if value == 0:
            continue
        if not SCATTER_OUTPUT_OFFSET <= output_index < scatter_end:
            raise ValueError(f"unexpected non-scatter difference at {output_index}")
        bit_index = output_index - SCATTER_OUTPUT_OFFSET
        expected = 1 << V39_MASK_BIT_ORDER[bit_index & 7]
        if value != expected:
            raise ValueError(
                f"invalid scatter byte at {output_index}: {value:#x} != {expected:#x}"
            )
        mask[bit_index >> 3] |= 1 << (bit_index & 7)
    return bytes(mask)


@dataclass(frozen=True)
class PayloadReplay:
    plaintext: bytes
    ciphertext: bytes
    transform_random: int
    scatter_mask: bytes

    @property
    def verified(self) -> bool:
        return transform_payload(
            self.plaintext, self.transform_random, self.scatter_mask
        ) == self.ciphertext

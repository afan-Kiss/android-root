"""Recover the v39 xor-loop raw scatter seed from the xmxor payload.

精简版: 只保留核心生成函数 (mix_payload_word + generate_raw_seed),
供 qishen_pure API 服务器自动推导 X-Perseus 的 raw_seed 使用。

源自 seven_gods/p9bc_scatter_seed_generator.py (P9bc 闭环验证 score=178)。
"""
from __future__ import annotations

SEED_LENGTH = 19
WORD_SIZE = 8
PAYLOAD_PREFIX_LENGTH = SEED_LENGTH * WORD_SIZE
# VM bit-selection mixer 输入 bit 位 (P9bc 逆向验证)
LOW_BIT_SOURCES = (60, 40, 51, 17, 34, 7, 30)


def mix_payload_word(word: int) -> int:
    """Apply the recovered 64-to-32-bit VM bit-selection mixer."""
    if not 0 <= word <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("payload word must fit in an unsigned 64-bit integer")
    mixed = ((word >> 13) << 7) & 0xFFFFFFFF
    for output_bit, input_bit in enumerate(LOW_BIT_SOURCES):
        mixed |= ((word >> input_bit) & 1) << output_bit
    return mixed


def generate_raw_seed(payload: bytes, seed_length: int = SEED_LENGTH) -> bytes:
    """Generate one seed byte from each little-endian 8-byte payload word."""
    required = seed_length * WORD_SIZE
    if len(payload) < required:
        raise ValueError(f"xmxor payload must contain at least {required} bytes")
    return bytes(
        mix_payload_word(
            int.from_bytes(payload[offset : offset + WORD_SIZE], "little")
        )
        & 0xFF
        for offset in range(0, required, WORD_SIZE)
    )

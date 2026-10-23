import base64
import hashlib
import random

from .common import pkcs7_pad


HEX_TABLE = b"0123456789abcdef"
U64 = 0xFFFFFFFFFFFFFFFF


def _ror64(value: int, count: int) -> int:
    count %= 64
    return ((value >> count) | (value << (64 - count))) & U64


def _bytes_to_u64_words(data: bytes):
    return [int.from_bytes(data[i:i + 8], "little") for i in range(0, len(data), 8)]


def _encrypt_block(round_keys, block: bytes) -> bytes:
    data0 = int.from_bytes(block[:8], "little")
    data1 = int.from_bytes(block[8:], "little")
    for key in round_keys[:0x22]:
        data1 = (key ^ (data0 + _ror64(data1, 8))) & U64
        data0 = (data1 ^ _ror64(data0, 61)) & U64
    return data0.to_bytes(8, "little") + data1.to_bytes(8, "little")


def _round_keys(seed: bytes):
    md5_digest = hashlib.md5(seed).digest()
    key_bytes = bytearray(32)
    for index, value in enumerate(md5_digest):
        key_bytes[index * 2] = HEX_TABLE[value >> 4]
        key_bytes[index * 2 + 1] = HEX_TABLE[value & 0x0F]

    pending = _bytes_to_u64_words(key_bytes)
    buffer_b0 = pending.pop(0)
    buffer_b8 = pending.pop(0)
    keys = [int.from_bytes(key_bytes[:8], "little")]

    for i in range(0x22):
        x9 = buffer_b0
        x8 = (_ror64(buffer_b8, 8) + x9) & U64
        x8 = (x8 ^ i) & U64
        pending.append(x8)
        x8 = (x8 ^ _ror64(x9, 61)) & U64
        keys.append(x8)
        buffer_b0 = x8
        buffer_b8 = pending.pop(0)
    return keys


class Helios:
    def get_value(self, timestamp: str, aid: str = "1128", license_id: str = "1588093228", rand: int = None) -> str:
        aid = str(aid or "1128")
        license_id = str(license_id or "1588093228")
        rand = rand or random.randint(0, 0xFFFFFFFF)

        rand_bytes = rand.to_bytes(4, "little")
        keys = _round_keys(rand_bytes + aid.encode())
        plaintext = pkcs7_pad(f"{int(timestamp)}-{license_id}-{aid}".encode(), 16)

        encrypted = bytearray()
        for i in range(0, len(plaintext), 16):
            encrypted += _encrypt_block(keys, plaintext[i:i + 16])

        return base64.b64encode(rand_bytes + encrypted).decode()

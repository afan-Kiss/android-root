import base64
import struct
from os import urandom

from .common import md5hex


class Ladon:
    @staticmethod
    def _validate(value):
        return value & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _ror(value, count):
        count %= 64
        low = (value << (64 - count)) & 0xFFFFFFFFFFFFFFFF
        value = (value >> count) & 0xFFFFFFFFFFFFFFFF
        return value | low

    @staticmethod
    def _encrypt_block(hash_table, input_data):
        data0 = int.from_bytes(input_data[:8], "little")
        data1 = int.from_bytes(input_data[8:], "little")
        for i in range(0x22):
            h = int.from_bytes(hash_table[i * 8:(i + 1) * 8], "little")
            data1 = Ladon._validate(h ^ (data0 + Ladon._ror(data1, 8)))
            data0 = Ladon._validate(data1 ^ Ladon._ror(data0, 0x3D))
        return data0.to_bytes(8, "little") + data1.to_bytes(8, "little")

    def get_value(self, timestamp: str, aid: str, lc_id: int = 1611921764) -> str:
        rand_bytes = urandom(4)
        data = f"{int(timestamp)}-{lc_id}-{aid}".encode()
        md5_key = md5hex(rand_bytes + str(aid).encode()).encode()

        hash_table = bytearray(272 + 16)
        hash_table[:32] = md5_key
        temp = [int.from_bytes(hash_table[i * 8:(i + 1) * 8], "little") for i in range(4)]
        buf_b0, buf_b8 = temp[0], temp[1]
        temp = temp[2:]

        for i in range(0x22):
            x9 = buf_b0
            x8 = buf_b8
            x8 = Ladon._validate(Ladon._ror(x8, 8))
            x8 = Ladon._validate(x8 + x9)
            x8 = Ladon._validate(x8 ^ i)
            temp.append(x8)
            x8 = Ladon._validate(x8 ^ Ladon._ror(x9, 61))
            struct.pack_into("<Q", hash_table, (i + 1) * 8, x8)
            buf_b0 = x8
            buf_b8 = temp.pop(0)

        pad_len = (16 - len(data) % 16) % 16
        padded = data + bytes([pad_len] * pad_len)

        output = bytearray(len(padded) + 4)
        output[:4] = rand_bytes
        for i in range(len(padded) // 16):
            output[4 + i * 16:4 + (i + 1) * 16] = Ladon._encrypt_block(hash_table, padded[i * 16:(i + 1) * 16])

        return base64.b64encode(bytes(output)).decode()

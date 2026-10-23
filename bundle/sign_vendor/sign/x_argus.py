import base64
import hashlib
import random
import struct


class SM3:
    IV = [1937774191, 1226093241, 388252375, 3666478592, 2842636476, 372324522, 3817729613, 2969243214]
    TJ = [2043430169] * 16 + [2055708042] * 48

    @staticmethod
    def _rotate_left(a, k):
        k %= 32
        return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))

    @staticmethod
    def _P0(x):
        return x ^ SM3._rotate_left(x, 9) ^ SM3._rotate_left(x, 17)

    @staticmethod
    def _P1(x):
        return x ^ SM3._rotate_left(x, 15) ^ SM3._rotate_left(x, 23)

    @staticmethod
    def _FF(x, y, z, j):
        return x ^ y ^ z if j < 16 else (x & y) | (x & z) | (y & z)

    @staticmethod
    def _GG(x, y, z, j):
        return x ^ y ^ z if j < 16 else (x & y) | ((~x) & z)

    @staticmethod
    def _CF(v, block):
        w = [int.from_bytes(block[i * 4:(i + 1) * 4], "big") for i in range(16)]
        for j in range(16, 68):
            w.append(w[j - 16] ^ w[j - 9] ^ SM3._rotate_left(w[j - 3], 15) ^ SM3._P1(w[j - 16] ^ SM3._rotate_left(w[j - 13], 7) ^ w[j - 6]))
        w1 = [w[j] ^ w[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            ss1 = SM3._rotate_left((SM3._rotate_left(a, 12) + e + SM3._rotate_left(SM3.TJ[j], j % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ SM3._rotate_left(a, 12)
            tt1 = (SM3._FF(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (SM3._GG(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = SM3._rotate_left(b, 9)
            b = a
            a = tt1
            h = g
            g = SM3._rotate_left(f, 19)
            f = e
            e = SM3._P0(tt2)
        return [a ^ v[0], b ^ v[1], c ^ v[2], d ^ v[3], e ^ v[4], f ^ v[5], g ^ v[6], h ^ v[7]]

    @staticmethod
    def hash(data: bytes) -> bytes:
        msg = bytearray(data)
        msg_len = len(data)
        msg.append(0x80)
        while len(msg) % 64 != 56:
            msg.append(0)
        msg += struct.pack(">Q", msg_len * 8)
        v = SM3.IV[:]
        for i in range(0, len(msg), 64):
            v = SM3._CF(v, msg[i:i + 64])
        return b"".join(struct.pack(">I", item) for item in v)


class Simon:
    @staticmethod
    def _rotate_left(v, n):
        return ((v << n) | (v >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _key_expansion(key):
        for i in range(4, 72):
            tmp = Simon._rotate_left(key[i - 1], 61)
            tmp = tmp ^ key[i - 3]
            tmp = tmp ^ Simon._rotate_left(tmp, 1)
            key[i] = (~key[i - 4]) & 0xFFFFFFFFFFFFFFFF ^ tmp ^ ((0x3DC94C3A046D678B >> ((i - 4) % 62)) & 1) ^ 3
        return key

    @staticmethod
    def encrypt(pt, k):
        key = [0] * 72
        key[0], key[1], key[2], key[3] = k
        key = Simon._key_expansion(key)
        x_i, x_i1 = pt
        for i in range(72):
            tmp = x_i1
            f = Simon._rotate_left(x_i1, 1) & Simon._rotate_left(x_i1, 8)
            x_i1 = x_i ^ f ^ Simon._rotate_left(x_i1, 2) ^ key[i]
            x_i = tmp
        return [x_i, x_i1]


class ProtoBuf:
    def __init__(self, data=None):
        self.fields = []
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, int):
                    self.fields.append((key, 0, value))
                elif isinstance(value, str):
                    self.fields.append((key, 2, value.encode()))
                elif isinstance(value, bytes):
                    self.fields.append((key, 2, value))
                elif isinstance(value, dict):
                    self.fields.append((key, 2, ProtoBuf(value).to_bytes()))

    def to_bytes(self):
        out = bytearray()
        for idx, field_type, value in self.fields:
            out.extend(self._encode_varint((idx << 3) | field_type))
            if field_type == 0:
                out.extend(self._encode_varint(value))
            elif field_type == 2:
                out.extend(self._encode_varint(len(value)))
                out.extend(value)
        return bytes(out)

    @staticmethod
    def _encode_varint(value):
        value &= 0xFFFFFFFF
        out = bytearray()
        while value > 0x80:
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        out.append(value & 0x7F)
        return out


class Argus:
    SIGN_KEY = b"\xac\x1a\xda\xae\x95\xa7\xaf\x94\xa5\x11J\xb3\xb3\xa9}\xd8\x00P\xaa\n91L@R\x8c\xae\xc9RV\xc2\x8c"

    @staticmethod
    def _encrypt_enc_pb(data: bytes, length: int) -> bytes:
        data = list(data)
        xor_array = data[:8]
        for i in range(8, length):
            data[i] ^= xor_array[i % 8]
        return bytes(data[::-1])

    def get_value(self, timestamp: str, aid: str, device_id: str, version_name: str, stub: str = "", query: str = "") -> str:
        ts = int(timestamp)
        body_hash = SM3.hash(bytes.fromhex(stub) if stub else bytes(16))[:6]
        query_hash = SM3.hash(query.encode() if query else bytes(16))[:6]

        pb = ProtoBuf({
            1: 0x20200929 << 1,
            2: 2,
            3: random.randint(0, 0x7FFFFFFF),
            4: str(aid),
            5: device_id,
            6: "1611921764",
            7: version_name,
            8: "v05.00.06-ov-android",
            9: 134744640,
            10: bytes(8),
            11: 0,
            12: ts << 1,
            13: body_hash,
            14: query_hash,
            15: {1: 1, 2: 1, 3: 1, 7: 3348294860},
            16: device_id if device_id else "",
            20: "none",
            21: 738,
            23: {1: "NX551J", 2: 8196, 4: 2162219008},
            25: 2,
        }).to_bytes()

        pad_len = (16 - len(pb) % 16) % 16
        pb_padded = pb + bytes([pad_len] * pad_len)

        sm3_key = SM3.hash(self.SIGN_KEY + b"\xf2\x81ao" + self.SIGN_KEY)
        key_list = []
        for i in range(2):
            key_list += list(struct.unpack("<QQ", sm3_key[i * 16:(i + 1) * 16]))

        enc_pb = bytearray(len(pb_padded))
        for i in range(len(pb_padded) // 16):
            pt = list(struct.unpack("<QQ", pb_padded[i * 16:(i + 1) * 16]))
            ct = Simon.encrypt(pt, key_list)
            enc_pb[i * 16:i * 16 + 8] = ct[0].to_bytes(8, "little")
            enc_pb[i * 16 + 8:i * 16 + 16] = ct[1].to_bytes(8, "little")

        buffer = self._encrypt_enc_pb(b"\xf2\xf7\xfc\xff\xf2\xf7\xfc\xff" + bytes(enc_pb), len(enc_pb) + 8)
        buffer = b"\xa6n\xad\x9fw\x01\xd0\x0c\x18" + buffer + b"ao"

        from Crypto.Cipher import AES
        aes_key = hashlib.md5(self.SIGN_KEY[:16]).digest()
        aes_iv = hashlib.md5(self.SIGN_KEY[16:]).digest()
        pad_len = (16 - len(buffer) % 16) % 16
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        encrypted = cipher.encrypt(buffer + bytes([pad_len] * pad_len))

        return base64.b64encode(b"\xf2\x81" + encrypted).decode()

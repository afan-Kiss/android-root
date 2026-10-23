# -*- encoding: utf-8 -*-
"""extra.py — SM3/MD5/RC4/AES辅助函数 (从dy34安卓v34迁移)"""
import binascii

from ._sm3_impl import SM3

from .branch_one import branch_one_table

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def rol(num, shift):
    shift %= 32
    return ((num << shift) | (num >> (32 - shift))) & 0xFFFFFFFF


def rl8(x: int, k: int) -> int:
    """8位循环左移"""
    n = 8
    s = k & (n - 1)
    return ((x << s) | (x >> (n - s))) & 0xff


def ror32(value, count):
    count %= 32
    low = value << (32 - count)
    value >>= count
    value |= low
    return value & 0xFFFFFFFF


def ror(value, count):
    """64位循环右移"""
    count %= 64
    low = value << (64 - count)
    value >>= count
    value |= low
    return value & 0xFFFFFFFFFFFFFFFF


def get_key_hash(key, rand):
    """Medusa密钥派生: SM3(key+rand+key) → 32字节key + 4字节seed"""
    to_hash = bytearray(68)
    to_hash[:32] = key
    to_hash[32:36] = rand.to_bytes(4, byteorder='little')
    to_hash[36:] = key

    d1 = (rand >> 16) & 0x000000ff
    d2 = (d1 << 11) | (rand >> 24)
    d2 ^= (d1 >> 5) ^ d1
    d2 = ~d2 & 0xffffffff

    return SM3(to_hash).digest(), d2.to_bytes(4, "little")


def md5sum(data):
    """MD5哈希,返回bytes"""
    import hashlib
    h = hashlib.md5()
    h.update(data)
    return h.digest()


def hash_f13_legacy_v34(query_sm3, body_md5_bytes, ts_bytes):
    """Return the old v34 16-byte placeholder retained for research scripts."""
    import hashlib
    h = hashlib.md5()
    h.update(query_sm3)
    h.update(body_md5_bytes)
    h.update(ts_bytes)
    return h.digest()[:16]


def f13_last2(khronos, lag=1):
    """f13 bytes 18..20: ((khronos - lag + 1) % 16) + 0x30, xor 0x34."""
    byte18 = ((int(khronos) - int(lag) + 1) % 16) + 0x30
    return bytes((byte18, byte18 ^ 0x34))


def hash_f13(query_sm3, body_md5_bytes, ts_bytes, khronos,
             observed_digest=None, lag=1):
    """v39 proto field13 (LEGACY / observed-digest path; NOT on the main sign
    chain — that goes through millless.field13_20b_from_first16).

    NOTE [2026-09-02]: the docstring claim 'first16 still needs mill seed' is
    OBSOLETE. _ab_f13_split.py 7-variant proved server does not validate first16
    entropy; urandom first16 + self-consistent hi16 ships. For offline first16
    use field13_20b_from_first16(os.urandom(16), ts, lag=1), not this function.
    last2 is 纯算 (ts-formula, the only server-checked part).
    """
    del query_sm3, body_md5_bytes, ts_bytes
    last2 = f13_last2(khronos, lag)
    if observed_digest is None:
        raise NotImplementedError(
            "v39 query_body_ts_hash first16 mill-seed is not yet recovered; "
            "provide the observed 16/18/20-byte field13 prefix"
        )
    digest = bytes(observed_digest)
    if len(digest) == 16:
        return digest + b"\x00\x00" + last2
    if len(digest) == 18:
        return digest + last2
    if len(digest) == 20:
        return digest[:18] + last2
    raise ValueError("v39 query_body_ts_hash prefix must be 16, 18 or 20 bytes")


def AES_V3(key, khronos):
    """AES加密 (v34实现)"""
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad

    class AESWrapper:
        def __init__(self, key, khronos):
            self.key = key
            self.khronos = khronos

        def encrypt(self, data, iv):
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return cipher.encrypt(pad(data, 16))

    return AESWrapper(key, khronos)

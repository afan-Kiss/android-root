# -*- coding: utf-8 -*-
"""send_code 用的 ttEncrypt 纯算。从 qishen_pure ttencrypt_pure 抽出，不整包引进。"""
from __future__ import annotations

import hashlib
import os

from Cryptodome.Cipher import AES

TT_DATA_MAGIC = bytes.fromhex("746305100000")
_KDF_TAIL64 = bytes.fromhex(
    "4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524"
    "f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58"
)
_PINNED_ENVELOPE_BY_TS = {
    1785304403: bytes.fromhex(
        "23e960b3cc1fe78d3486fd44cb37a25bf9db7f9076c69cc34031b51bbaead5dd"
    ),
}


def _pkcs_pad(plaintext: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(plaintext) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return plaintext + bytes([pad_len] * pad_len)


def _derive_aes_key_iv(rand32: bytes) -> tuple[bytes, bytes]:
    rnd = bytes(rand32[:32])
    h1 = hashlib.sha512(rnd).digest()
    h2 = hashlib.sha512(h1 + _KDF_TAIL64).digest()
    return h2[:16], h2[16:32]


def encrypt_payload_pure(
    plaintext: bytes,
    *,
    timestamp_sec: int,
    iv_u16: int | None = None,
    rand32: bytes | None = None,
) -> bytes:
    del iv_u16
    ts = int(timestamp_sec)
    rnd = bytes(rand32) if rand32 is not None else _PINNED_ENVELOPE_BY_TS.get(ts)
    if rnd is None:
        rnd = os.urandom(32)
    rnd = bytes(rnd[:32])
    key, iv = _derive_aes_key_iv(rnd)
    pre = hashlib.sha512(bytes(plaintext)).digest() + bytes(plaintext)
    body = AES.new(key, AES.MODE_CBC, iv).encrypt(_pkcs_pad(pre, 16))
    return TT_DATA_MAGIC + rnd + body

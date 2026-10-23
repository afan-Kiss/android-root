# -*- encoding: utf-8 -*-
"""gorgonEncrypt.py — X-Gorgon纯算实现 (从dy34安卓v34迁移)

X-Gorgon: 48字节hex, 前缀8404
- 输入: query的MD5前4字节 + body的MD5前4字节 + 版本 + 时间戳
- 加密: RC4 + 位运算混淆
- 依赖: header.xssstub_hash_md5_hex
"""
import hashlib
from .header import xssstub_hash_md5_hex


def rc4_xg(data, key):
    """X-Gorgon专用RC4"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i] = S[j]
    i = j = 0
    result = bytearray(len(data))
    for k, v in enumerate(data):
        i += 1
        x = S[i]
        j += x
        y = S[j & 0xff]
        S[i] = y
        result[k] = v ^ S[(y + y) & 0xff]
    return result


def reverse_bits(num):
    """8位翻转"""
    bin_num = bin(num)[2:].zfill(8)
    rev_bin_num = bin_num[::-1]
    return int(rev_bin_num, 2)


gorgon_84 = bytes([0x4a, 0x16, 0x47, 0x6c, 0x84, 0x04])


def encrypt_gorgon(body, query, khronos, xg_rand, dataType,
                   xg_seed=0, mssdk_version_int=0x040a0100):
    """
    生成 X-Gorgon.

    Args:
        body: 请求体(dict/str/bytes/None)
        query: URL query字符串(已url_encode)
        khronos: 时间戳(秒)
        xg_rand: 2字节随机数(0..0xFFFF)
        dataType: 请求体类型(如"application/json; charset=UTF-8")
        xg_seed: X-Gorgon种子(默认0, v39真机样本验证)
        mssdk_version_int: mssdk版本int(默认0x040a0100=v04.10.01, 真实样本10暴力扫描匹配)

    Returns:
        48字符hex字符串 (X-Gorgon header值)

    已验证: player/settings与general/search样本均字节级完全匹配
    (xg_seed=0, mssdk_version_int=0x040a0100)
    """
    body_md5 = xssstub_hash_md5_hex(data=body, dataType=dataType).lower() if body else ""
    data = hashlib.md5(query.encode()).digest()[:4]
    if len(body_md5) > 0:
        body_md5 = bytes.fromhex(body_md5)
        data += body_md5[:4]
    else:
        data += bytearray([0, 0, 0, 0])
    data += bytearray([0, 0, 0, 0])
    data += mssdk_version_int.to_bytes(4, "little")
    data += khronos.to_bytes(4, "big")
    key = bytes([
        gorgon_84[0],
        xg_seed & 0xff,
        gorgon_84[1],
        (xg_rand >> 8) & 0xff,
        gorgon_84[2],
        gorgon_84[3],
        (xg_seed >> 8) & 0xff,
        xg_rand & 0xff,
    ])
    out = rc4_xg(data, key)
    for i in range(len(out)):
        a = out[i]
        out[i] = (a >> 4 | (a << 4)) & 0xFF
        a = out[0]
        if i + 1 < len(out):
            a = out[i + 1]
        a ^= out[i]
        a = reverse_bits(a)
        out[i] = (~(a ^ 20)) & 0xFF
    ret = gorgon_84[-2:]
    ret += xg_rand.to_bytes(2, "little")
    ret += xg_seed.to_bytes(2, "little")
    ret += out
    return ret.hex()

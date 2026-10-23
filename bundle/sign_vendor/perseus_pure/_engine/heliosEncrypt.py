# -*- encoding: utf-8 -*-
"""heliosEncrypt.py — X-Helios v39纯算实现

已验证: 4组真实样本字节级匹配 (2026-06-17抓包)
- license_id = 1588093228 (v34=v39, 未轮换)
- aid = 1128
- 算法: 自定义ARX (0x22=34轮 ror(8)/ror(61)/xor)
- 输入: pad(f"{khronos}-{license_id}-1128", 16)
- 密钥派生: MD5(rand(4B,LE) + "1128") → 32字节hex展开 → hash_table(35个uint64)
- 输出: rand(4B) + ARX加密(每块16B) → base64
"""
import base64
import hashlib
import random

# ============ 常量 ============
LICENSE_ID = "1588093228"   # v34=v39 (未轮换, 已4样本验证)
AID = "1128"                # 抖音aid
ARX_ROUNDS = 0x22           # 34轮

HexTable = b"0123456789abcdef"


# ============ ARX 核心算法 ============
def ror(value: int, count: int) -> int:
    """64位循环右移"""
    count %= 64
    if count == 0:
        return value & 0xFFFFFFFFFFFFFFFF
    low = value << (64 - count)
    value >>= count
    value |= low
    return value & 0xFFFFFFFFFFFFFFFF


def bytes2matrix(text: bytes) -> list:
    """字节序列转uint64列表(小端)"""
    return [int.from_bytes(text[i:i + 8], 'little') for i in range(0, len(text), 8)]


def encrypt_helios_block(hash_table: list, in_data: bytes) -> bytes:
    """
    ARX单块加密 (16字节 → 16字节)
    0x22轮: data1 = hash[i] ^ (data0 + ror(data1,8)); data0 = data1 ^ ror(data0,61)
    """
    data0 = int.from_bytes(in_data[:8], 'little')
    data1 = int.from_bytes(in_data[8:], 'little')
    for i in range(ARX_ROUNDS):
        hash1 = hash_table[i]
        data1 = hash1 ^ (data0 + ror(data1, 8))
        data1 &= 0xFFFFFFFFFFFFFFFF
        data0 = data1 ^ ror(data0, 61)
        data0 &= 0xFFFFFFFFFFFFFFFF
    return data0.to_bytes(8, 'little') + data1.to_bytes(8, 'little')


def build_hash_table(rand_bytes: bytes) -> list:
    """
    从rand(4B,LE)派生hash_table(35个uint64)
    1. data = rand_bytes + b"1128"
    2. key_sum = MD5(data) (16B)
    3. keys = 把16B展开成32B hex字符串 (每个字节→2个hex字符)
    4. hash_table[0] = uint64(keys[:8])
    5. 迭代0x22次生成剩余34个uint64 (ARX密钥扩展)
    """
    data = rand_bytes + AID.encode()
    key_sum = hashlib.md5(data).digest()  # 16字节

    # 16字节 → 32字节hex展开
    keys = bytearray(32)
    for i in range(16):
        v1 = key_sum[i]
        keys[2 * i] = HexTable[v1 >> 4]
        keys[2 * i + 1] = HexTable[v1 & 15]

    hash_table = [int.from_bytes(keys[:8], "little")]
    keys_m = bytes2matrix(keys)
    buffer_b0 = keys_m[0]
    buffer_b8 = keys_m[1]
    keys_m.pop(0)
    keys_m.pop(0)

    for i in range(ARX_ROUNDS):
        x9 = buffer_b0
        x8 = buffer_b8
        x8 = ror(x8, 8)
        x8 = (x8 + x9) & 0xFFFFFFFFFFFFFFFF
        x8 = (x8 ^ i) & 0xFFFFFFFFFFFFFFFF
        keys_m.append(x8)
        x8 = x8 ^ ror(x9, 61)
        x8 &= 0xFFFFFFFFFFFFFFFF
        hash_table.append(x8)
        buffer_b0 = x8
        buffer_b8 = keys_m[0]
        keys_m.pop(0)

    return hash_table


# ============ PKCS7 Padding ============
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


# ============ 主入口 ============
def encrypt_helios(khronos: int, rand: int = None, license_id: str = LICENSE_ID) -> str:
    """
    生成 v39 X-Helios.

    Args:
        khronos: 时间戳(秒), 与x-khronos header一致
        rand: 4字节随机数(0..0xFFFFFFFF), None=随机
        license_id: 默认1588093228 (v34=v39, 已验证)

    Returns:
        48字符Base64字符串 (X-Helios header值)

    算法:
        in_data = pad(f"{khronos}-{license_id}-1128", 16)
        rand_bytes = rand.to_bytes(4, 'little')
        hash_table = build_hash_table(rand_bytes)
        out = rand_bytes + Σ encrypt_helios_block(hash_table, block_i)
        return base64(out)
    """
    if rand is None:
        rand = random.randint(0, 0xFFFFFFFF)

    rand_bytes = rand.to_bytes(4, 'little')
    hash_table = build_hash_table(rand_bytes)

    in_data = pkcs7_pad(f"{khronos}-{license_id}-{AID}".encode(), 16)

    out = bytearray(rand_bytes)
    for i in range(len(in_data) // 16):
        block = in_data[i * 16:i * 16 + 16]
        out += encrypt_helios_block(hash_table, block)

    return base64.b64encode(bytes(out)).decode()

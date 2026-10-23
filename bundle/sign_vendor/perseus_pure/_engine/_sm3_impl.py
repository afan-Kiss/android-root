# -*- coding: utf-8 -*-
"""SM3 密码杂凑算法实现 (内联自 pysmx.SM3._SM3, 作者: 河北雪域网络科技有限公司 A.Star)
   GB/T 32905-2016 SM3 密码杂凑算法
"""
from math import ceil
from functools import reduce
from copy import copy
import struct

BIT_EACH_32 = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144,
               524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456,
               536870912, 1073741824, 2147483648, 4294967296]

_IV = "7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e"
_IV = int(_IV.replace(" ", ""), 16)
_IV = [(_IV >> ((7 - i) * 32)) & 0xFFFFFFFF for i in range(8)]


def _rotate_left(a, k):
    k %= 32
    high, low = divmod(a, BIT_EACH_32[32 - k])
    return high + low * BIT_EACH_32[k]


_T_j = [0x79cc4519] * 16 + [0x7a879d8a] * 48
_T_j_rotate_left = [_rotate_left(Tj, j) for j, Tj in enumerate(_T_j)]


def _P_0(X):
    high, low = divmod(X, BIT_EACH_32[23])
    r_l_9 = high + low * BIT_EACH_32[9]
    high, low = divmod(X, BIT_EACH_32[15])
    r_l_17 = high + low * BIT_EACH_32[17]
    return X ^ r_l_9 ^ r_l_17


def _P_1(X):
    high, low = divmod(X, BIT_EACH_32[17])
    r_l_15 = high + low * BIT_EACH_32[15]
    high, low = divmod(X, BIT_EACH_32[9])
    r_l_23 = high + low * BIT_EACH_32[23]
    return X ^ r_l_15 ^ r_l_23


def _PUT_UINT32_BE(n):
    return [int((n >> 24) & 0xff), int((n >> 16) & 0xff), int((n >> 8) & 0xff), int(n & 0xff)]


def _str2bytes(msg, encoding='utf-8'):
    if isinstance(msg, str):
        msg = msg.encode(encoding)
    return list(msg)


def _hex2byte(msg):
    if not isinstance(msg, str):
        raise ValueError('message must be string')
    ml = len(msg)
    if (ml & 1) != 0:
        msg = '0' + msg
    return list(bytes.fromhex(msg))


def _cf(V_i, B_i):
    W = [(B_i[ind] * BIT_EACH_32[24]) + (B_i[ind + 1] * BIT_EACH_32[16]) + (B_i[ind + 2] * BIT_EACH_32[8]) + (
        B_i[ind + 3]) for ind in range(0, 64, 4)]
    for j in range(16, 68):
        high_W3_15, low_W3_15 = divmod(W[-3], BIT_EACH_32[17])
        high_W13_7, low_W13_7 = divmod(W[-13], BIT_EACH_32[25])
        X = W[- 16] ^ W[- 9] ^ (high_W3_15 + low_W3_15 * BIT_EACH_32[15])
        high_P1_15, low_P1_15 = divmod(X, BIT_EACH_32[17])
        r_l_15 = high_P1_15 + low_P1_15 * BIT_EACH_32[15]
        high_P1_23, low_P1_23 = divmod(X, BIT_EACH_32[9])
        r_l_23 = high_P1_23 + low_P1_23 * BIT_EACH_32[23]
        W.append(X ^ r_l_15 ^ r_l_23 ^ (high_W13_7 + low_W13_7 * BIT_EACH_32[7]) ^ W[- 6])
    W_1 = [W[j] ^ W[j + 4] for j in range(64)]
    A, B, C, D, E, F, G, H = V_i
    for j in range(0, 16):
        high_A12, low_A12 = divmod(A, BIT_EACH_32[20])
        r_l_12 = high_A12 + low_A12 * BIT_EACH_32[12]
        high, low = divmod((r_l_12 + E + _T_j_rotate_left[j]) & 0xFFFFFFFF, BIT_EACH_32[25])
        SS1 = high + low * BIT_EACH_32[7]
        SS2 = SS1 ^ r_l_12
        TT1 = ((A ^ B ^ C) + D + SS2 + W_1[j]) & 0xFFFFFFFF
        TT2 = ((E ^ F ^ G) + H + SS1 + W[j]) & 0xFFFFFFFF
        high_B9, low_B9 = divmod(B, BIT_EACH_32[23])
        high_F19, low_F19 = divmod(F, BIT_EACH_32[13])
        high, low = divmod(TT2, BIT_EACH_32[23])
        r_l_9 = high + low * BIT_EACH_32[9]
        high, low = divmod(TT2, BIT_EACH_32[15])
        r_l_17 = high + low * BIT_EACH_32[17]
        A, B, C, D, E, F, G, H = TT1, A, high_B9 + low_B9 * BIT_EACH_32[9] & 0xffffffff, C, (
                    TT2 ^ r_l_9 ^ r_l_17) & 0xffffffff, E, high_F19 + low_F19 * BIT_EACH_32[19] & 0xffffffff, G
    for j in range(16, 64):
        high_A12, low_A12 = divmod(A, BIT_EACH_32[20])
        r_l_12 = high_A12 + low_A12 * BIT_EACH_32[12]
        high, low = divmod((r_l_12 + E + _T_j_rotate_left[j]) & 0xFFFFFFFF, BIT_EACH_32[25])
        SS1 = high + low * BIT_EACH_32[7]
        SS2 = SS1 ^ r_l_12
        TT1 = (((A & B) | (A & C) | (B & C)) + D + SS2 + W_1[j]) & 0xFFFFFFFF
        TT2 = (((E & F) | ((~ E) & G)) + H + SS1 + W[j]) & 0xFFFFFFFF
        high_B9, low_B9 = divmod(B, BIT_EACH_32[23])
        high_F19, low_F19 = divmod(F, BIT_EACH_32[13])
        high, low = divmod(TT2, BIT_EACH_32[23])
        r_l_9 = high + low * BIT_EACH_32[9]
        high, low = divmod(TT2, BIT_EACH_32[15])
        r_l_17 = high + low * BIT_EACH_32[17]
        A, B, C, D, E, F, G, H = TT1, A, high_B9 + low_B9 * BIT_EACH_32[9] & 0xffffffff, C, (
                    TT2 ^ r_l_9 ^ r_l_17) & 0xffffffff, E, high_F19 + low_F19 * BIT_EACH_32[19] & 0xffffffff, G
    return [A ^ V_i[0], B ^ V_i[1], C ^ V_i[2],
            D ^ V_i[3], E ^ V_i[4], F ^ V_i[5], G ^ V_i[6], H ^ V_i[7]]


def _digest(msg, Hexstr=0):
    if isinstance(msg, list):
        pass
    else:
        msg = _hex2byte(msg) if Hexstr else _str2bytes(msg)
    len1 = len(msg)
    msg.append(0x80)
    reserve1 = len1 % 64 + 1
    range_end = 56 if reserve1 <= 56 else 120
    msg.extend([0] * (range_end - reserve1))
    bit_length = len1 * 8
    msg.extend(struct.pack(">Q", bit_length))
    B = (msg[i:i + 64] for i in range(0, len(msg), 64))
    y = reduce(_cf, B, _IV)
    b = bytearray()
    [b.extend(_PUT_UINT32_BE(each)) for each in y]
    return bytes(b)


class SM3:
    """SM3 密码杂凑算法 (GB/T 32905-2016)
    用法: SM3(data).digest() -> 32 字节哈希
    """
    name = 'SM3'
    digest_size = 32
    block_size = 64

    def __init__(self, msg=b'', encoding='utf-8'):
        self.encoding = encoding
        self.msg = bytearray(_str2bytes(msg, self.encoding))

    def update(self, msg):
        self.msg.extend(_str2bytes(msg, self.encoding))

    def digest(self):
        return _digest(self.msg, 0)

    def hexdigest(self):
        return _digest(self.msg, 0).hex()

    def copy(self):
        return copy(self)

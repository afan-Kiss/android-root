# -*- coding: utf-8 -*-
# ==============================================================================
# 归档编号: 02
# 算法名称: X-Gorgon 签名
# 算法类型: 抖音六神签名之一
# 加密原语: RC4 + 字节反转混淆 + MD5
# 使用场景: 抖音 API 请求签名头 X-Gorgon
# 依赖:     无外部依赖（仅标准库 random, struct, hashlib.md5）
# ==============================================================================
# 算法说明:
#   X-Gorgon 签名使用 RC4 流密码 + 字节反转混淆对请求摘要进行加密。
#
#   加密流程:
#     1. 构造 20 字节的 gorgonArr:
#        - url 的 MD5 前 8 字节（hex 前 8 字符）
#        - data 的 MD5 前 8 字节（hex 前 8 字符）
#        - cookie 的 MD5 前 4 字节
#        - 固定字节 00000504 (版本标识)
#        - 时间戳 xk (big-endian 4 字节)
#     2. 生成 8 字节 RC4 密钥: [74, 0, 22, rand1, 71, 108, 0, rand2]
#        其中 rand1 随机，rand2 从 [0,32,64,96,128,160,192,224] 中随机选取
#     3. 用 RC4 加密 gorgonArr
#     4. 对密文做 encrypt_barr 字节混淆:
#        - 每个字节高低 4 位交换 (reverse)
#        - 与下一字节异或
#        - 4 位组内比特反转 (reverse_bit)
#        - 异或 0xEB (235)
#     5. 拼装最终结果: 版本号 8404 + keyData(rand2+rand1) + 0000 + 混淆后数据
#     6. 返回 hex 字符串
# ==============================================================================
import random
import struct
from copy import deepcopy
from hashlib import md5


def key_schedular(key):
    # RC4 密钥调度算法
    j = 0
    s = [i for i in range(256)]
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def pseudo_random_generator(s, input):
    # RC4 伪随机数生成算法
    i, j = (0, 0)
    key_stream = []
    for k in range(0, len(input)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) % 256
        key_stream.append(s[t])
    return key_stream


def encryption(key, plain_text):
    # RC4 加密
    uni_key = [c for c in key]
    s = key_schedular(uni_key)
    key_stream = pseudo_random_generator(s, plain_text)
    ciphertext = []
    for i in range(len(plain_text)):
        ciphertext.append(key_stream[i] ^ plain_text[i])
    return bytearray(ciphertext)


def reverse(byte):
    # 字节高低 4 位交换
    binary_str = bin(byte)[2:].zfill(8)
    left_reverse = binary_str[:4]
    right_reverse = binary_str[4:]
    new_binary_str = right_reverse + left_reverse
    return int(new_binary_str, 2)


def reverse_bit(b):
    # 4 位组内比特反转
    binary_str = bin(b)[2:].zfill(8)
    left_reverse = binary_str[:4][::-1]
    right_reverse = binary_str[4:][::-1]
    new_binary_str = right_reverse + left_reverse
    new_byte = int(new_binary_str, 2)
    return new_byte


def encrypt_barr(input):
    # 字节数组加密（字节反转 + 异或混淆）
    arr = deepcopy(input)
    length = len(arr)
    for i in range(length):
        a = reverse(arr[i])
        b = arr[(i + 1) % length]
        arr[i] = (reverse_bit(a ^ b) ^ 235) & 255
    return arr


def XG(xk, url, data, cookie):
    """X-Gorgon 签名生成

    :param xk: 时间戳（秒）
    :param url: URL 的 query 部分
    :param data: 请求体
    :param cookie: cookie 字符串/元组/列表
    :return: X-Gorgon hex 字符串
    """
    gorgonArr = bytearray()
    zeroPad = bytearray([0] * 4)
    if url:
        gorgonArr += bytes.fromhex(md5(bytearray(url, "UTF-8")).hexdigest()[:8])
    else:
        gorgonArr += zeroPad
    if data:
        gorgonArr += bytes.fromhex(md5(bytearray(data, "UTF-8")).hexdigest()[:8])
    else:
        gorgonArr += zeroPad
    if cookie:
        # cookie 可能是字符串、元组或列表，统一转为字符串
        if isinstance(cookie, (tuple, list)):
            cookie_str = "".join(str(c) for c in cookie if c)
        else:
            cookie_str = str(cookie)
        if cookie_str:
            gorgonArr += bytes(md5(bytearray(cookie_str, "UTF-8")).hexdigest(), "UTF-8")[:4]
        else:
            gorgonArr += zeroPad
    else:
        gorgonArr += zeroPad
    gorgonArr += bytes.fromhex("00000504")
    gorgonArr += struct.pack(">I", int(xk))
    s1 = [0, 32, 64, 96, 128, 160, 192, 224]
    rand1 = random.randint(0, 255)
    rand2 = s1[random.randint(0, 7)]
    rc4Key = [74, 0, 22, rand1, 71, 108, 0, rand2]
    cipherText = encryption(rc4Key, gorgonArr)
    arr = encrypt_barr(cipherText)
    versionCode = bytes.fromhex("8404")
    keyData = rand2.to_bytes(1, "little") + rand1.to_bytes(1, "little")
    xg = versionCode + keyData + bytes.fromhex("0000") + arr
    return xg.hex()


def get_xgorgon(xk, url, data, cookie=('', '')):
    """X-Gorgon 入口函数

    :param xk: 时间戳（秒）
    :param url: 完整 URL（会取 ? 后的 query 部分）
    :param data: 请求体
    :param cookie: cookie 字符串/元组/列表，默认 ('', '')
    :return: X-Gorgon hex 字符串
    """
    return XG(xk, url.split("?")[1], data, cookie)


if __name__ == "__main__":
    # 自测示例
    import time
    xk = int(time.time())
    demo_url = "https://api.amemv.com/aweme/v1/?aid=1128&device_id=1234567890123456789"
    demo_data = ""
    print(f"xk        = {xk}")
    print(f"X-Gorgon  = {get_xgorgon(xk, demo_url, demo_data)}")
# -*- encoding: utf-8 -*-
"""medusaEncrypt.py — X-Medusa纯算实现 (从dy34安卓v34迁移)

X-Medusa: protobuf + AES-CBC + 自定义混淆
- 输入: URL query + body + 时间戳 + 设备信息
- 加密: protobuf序列化 → xmxor混淆 → AES-CBC
- 输出: base64
"""
import base64
import hashlib
import os
import random
import time
from dataclasses import dataclass
from .proto import (
    Medusa,
    Report,
    Device,
    MedushaAlgorithmCount,
    Env
)
from .extra import (
    rl8,
    SM3,
    hash_f13,
    md5sum,
    get_key_hash,
    AES_V3
)
from .header import xssstub_hash_md5_hex

class FailClosedError(Exception):
    """Pure engine input/state failure."""

def compute_field13(input_data: bytes) -> bytes:
    """Compute builder/session SHA1 (20 bytes) from 12B input_data.

    Verified by P9r (R1+R2 dynamic analysis, 30/30 match, 100%):
      - digest = SHA1(input_data), pure SHA1 (NOT HMAC-SHA1)
      - Native call convention: ``0x256738(input_data, input_len, output_buf)``
      - Sample (12B input → 20B SHA1):
          input  = c9a450ec313132386e8f7974
          SHA1   = 0f4c1ed598bf1bff2642b140f02902c114797ab9

    Important: this digest is **not** Medusa protobuf ``query_body_ts_hash``
    (proto field13). Live field13 is a distinct per-request xor34-20B value;
    do not pass ``compute_field13(...)`` into ``gen_medusa_proto_v39``.
    """
    if not isinstance(input_data, (bytes, bytearray)):
        raise TypeError("input_data must be bytes")
    return hashlib.sha1(bytes(input_data)).digest()


def compute_byte18_byte19(local_ts_sec: int, lag: int = 0) -> bytes:
    """计算 byte18 和 byte19 (P9v V2 闭环验证, 16/16 100%)。

    公式 (P9v V2 通过 lag 反推法 16/16 验证):
      - byte18 = ((server_ts_sec + 1) % 16) + 0x30
      - 等效纯算: byte18 = ((local_ts_sec - lag + 1) % 16) + 0x30, lag ∈ {0, 1}
      - byte19 = byte18 ^ 0x34

    其中 lag 为服务器-本地时间偏差 (秒), P9v V2 16 样本统计:
      lag 分布 [0,1,1,0,1,1,0,0,1,1,0,0,1,1,1,1], 平均 0.6s,
      lag=0 占 37.5%, lag=1 占 62.5%, 无 lag≥2 样本。

    Args:
        local_ts_sec: 本地时间戳 (秒, 非负整数)。
        lag: 服务器-本地时间偏差 (仅允许 0 或 1, 默认 0)。

    Returns:
        2 字节 bytes: (byte18, byte19)。

    Raises:
        TypeError: local_ts_sec 或 lag 不是整数。
        ValueError: local_ts_sec 为负, 或 lag 不在 {0, 1}。
    """
    if not isinstance(local_ts_sec, int) or isinstance(local_ts_sec, bool):
        raise TypeError("local_ts_sec 必须是整数")
    if not isinstance(lag, int) or isinstance(lag, bool):
        raise TypeError("lag 必须是整数")
    if local_ts_sec < 0:
        raise ValueError("local_ts_sec 必须是非负整数")
    if lag not in (0, 1):
        raise ValueError("lag 必须是 0 或 1")
    byte18 = ((local_ts_sec - lag + 1) % 16) + 0x30
    byte19 = byte18 ^ 0x34
    return bytes((byte18, byte19))


# ---------------------------------------------------------------------------
# X-Medusa envelope 已知部分路径整合 (P9x X4)
# ---------------------------------------------------------------------------
# 已知字段 (P9r / P9v V2 / P9v V4 / P9t T4 已验证):
#   - builder_sha1 : 20B SHA1(input_data) (P9r, 用作 envelope 加密密钥源)
#   - byte18/19    : 2B  ((local_ts_sec - lag + 1) % 16) + 0x30, byte18 ^ 0x34
#   - hex_sha1     : 40B ASCII hex encoded SHA1 (Path A, P9t T4)
# 未知字段 (fail-closed, 必须抛 FailClosedError):
#   - proto_buffer_field13 : X1 进行中 (writer 虚函数地址未定位)
#   - envelope_full        : X2 进行中 (builder SHA1 加密算法未还原)
# ---------------------------------------------------------------------------

# builder 路径的 input_data 长度 (session_id+mid+suffix, P9r 实测 12B)
_BUILDER_INPUT_DATA_LEN = 12

# Path A hex 编码使用的字符表 (P9t T4 验证: 0123456789abcdef)
_HEX_CHAR_TABLE = "0123456789abcdef"

# Path A hex 编码后长度 (20B SHA1 → 40 字符)
_HEX_SHA1_LEN = 40


@dataclass
class MedusaEnvelopePartial:
    """X-Medusa envelope 已知部分字段 (P9x X4 整合).

    封装 P9r/P9v V2/P9v V4/P9t T4 已经验证的字段, 同时通过 fail-closed
    契约显式拒绝访问尚未还原的字段 (proto_buffer_field13 / envelope_full).

    已知字段 (可直接访问):
        builder_sha1 : 20 字节 SHA1(input_data), 用作 envelope 加密密钥源
                       (P9v V4 验证: 不直接出现在 header 字节中, 时间相关性
                       0-2ms, 推断为 AES/XXTEA 加密密钥/Mask)
        byte18       : envelope header 第 18 字节
                       (P9v V2 公式: ((local_ts_sec - lag + 1) % 16) + 0x30)
        byte19       : envelope header 第 19 字节 (= byte18 ^ 0x34)
        hex_sha1     : 40 字节 ASCII, Path A hex 编码 SHA1 (P9t T4 验证)
        input_data   : 12 字节 builder 输入 (session_id+mid+suffix)
        local_ts_sec : 本地时间戳 (秒, 用于 byte18/19 计算)
        lag          : 服务器-本地时间偏差 (0 或 1)

    未知字段 (访问抛 ``FailClosedError``, 不允许 silent default):
        proto_buffer_field13 : protobuf field13 真实 writer 函数地址 (X1 进行中)
        envelope_full         : builder SHA1 加密后完整 envelope (X2 进行中)
    """

    builder_sha1: bytes
    byte18: int
    byte19: int
    hex_sha1: bytes
    input_data: bytes
    local_ts_sec: int
    lag: int

    # 已知字段名集合 (允许通过 __getitem__ 访问)
    KNOWN_FIELDS = frozenset({
        "builder_sha1", "byte18", "byte19", "hex_sha1",
        "input_data", "local_ts_sec", "lag",
    })

    # 未知字段名集合 (访问时抛 FailClosedError)
    UNKNOWN_FIELDS = frozenset({
        "proto_buffer_field13",  # X1 进行中: writer 虚函数地址未定位
        "envelope_full",         # X2 进行中: builder SHA1 加密算法未还原
    })

    def to_dict(self) -> dict:
        """返回已知字段组成的 dict (不包含未知字段)."""
        return {
            "builder_sha1": self.builder_sha1,
            "byte18": self.byte18,
            "byte19": self.byte19,
            "hex_sha1": self.hex_sha1,
            "input_data": self.input_data,
            "local_ts_sec": self.local_ts_sec,
            "lag": self.lag,
        }

    def __getitem__(self, key: str) -> object:
        """dict 风格访问: 已知字段返回值, 未知字段抛 FailClosedError."""
        if key in self.UNKNOWN_FIELDS:
            # 延迟解析 FailClosedError, 保证与 qishen_api 引用的是同一类
            raise _resolve_fail_closed_error()(
                f"未知字段 {key!r} 不可用 — "
                f"{'X1' if key == 'proto_buffer_field13' else 'X2'} 进行中"
            )
        if key in self.KNOWN_FIELDS:
            return getattr(self, key)
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        return key in self.KNOWN_FIELDS

    def get_proto_buffer_field13(self) -> bytes:
        """未完成: protobuf field13 真实 writer 函数地址未定位 (X1 进行中).

        P9v V4 §10 已证明 builder SHA1 (常量) ≠ field13 (每次变化),
        field13 由独立的 writer 函数写入 protobuf; writer 虚函数地址
        (X1 子 agent) 尚未定位, 此处保持 fail-closed.
        """
        raise _resolve_fail_closed_error()(
            "proto_buffer_field13 不可用 — X1 进行中 "
            "(writer 虚函数地址未定位, P9v V4 已证明 builder_sha1 ≠ field13)"
        )

    def get_envelope_full(self) -> bytes:
        """未完成: builder SHA1 加密算法 (AES/xmxor?) 未还原 (X2 进行中).

        P9v V4 §10 推断 builder SHA1 用作 envelope 加密密钥/Mask, 但具体
        加密路径 (AES-CBC / XXTEA / xmxor 扩展) 尚未还原; envelope 闭包构造
        (X3) 也未完成. 此处保持 fail-closed.
        """
        raise _resolve_fail_closed_error()(
            "envelope_full 不可用 — X2 进行中 "
            "(builder SHA1 加密算法未还原, X3 obj 闭包构造未完成)"
        )


def compute_medusa_envelope_partial(
    input_data: bytes,
    local_ts_sec: int,
    lag: int = 0,
) -> MedusaEnvelopePartial:
    """整合 X-Medusa envelope 已知部分路径 (P9x X4).

    将已验证的子算法 (P9r SHA1 / P9v V2 byte18-19 / P9t T4 hex 编码)
    整合为单一 envelope 视图, 便于上层 (e2e 对拍 / MedusaSessionState)
    统一消费; 未还原字段保持 fail-closed.

    Args:
        input_data: builder 路径输入 (12B = session_id+mid+suffix).
                    若为空或非 bytes, 由下游 ``compute_field13`` /
                    ``compute_byte18_byte19`` 抛 TypeError/ValueError.
        local_ts_sec: 本地时间戳 (秒, 非负整数).
        lag: 服务器-本地时间偏差 (仅允许 0 或 1, 默认 0).

    Returns:
        ``MedusaEnvelopePartial`` 实例, 含 7 个已知字段 + 2 个 fail-closed
        访问器 (``get_proto_buffer_field13`` / ``get_envelope_full``).

    Raises:
        TypeError: input_data 非 bytes/bytearray, 或 ts/lag 非整数.
        ValueError: ts 为负, 或 lag 不在 {0, 1}。

    Note:
        - builder_sha1 用作 envelope 加密密钥源 (P9v V4), 不是 field13 数据
        - hex_sha1 是 Path A 路径 (w1=1, 非缓存键路径) 的中间产物
        - proto_buffer_field13 / envelope_full 未完成, 见 X1/X2/X3 进度
    """
    # 1. builder SHA1 (P9r 100% 验证, 20B)
    builder_sha1 = compute_field13(input_data)

    # 2. byte18/19 (P9v V2 16/16 验证, 2B)
    b18_19 = compute_byte18_byte19(local_ts_sec, lag)
    byte18 = b18_19[0]
    byte19 = b18_19[1]

    # 3. Path A hex 编码 SHA1 (P9t T4: 0x19d3e4, 20B → 40 字符 ASCII)
    #    使用标准 hex 字符表 (与 0x19d3e4 表完全一致: 0123456789abcdef)
    hex_sha1 = builder_sha1.hex().encode("ascii")
    if len(hex_sha1) != _HEX_SHA1_LEN:
        # 不变量保护: SHA1 输出固定 20B, hex 后必为 40B
        raise AssertionError(
            f"hex_sha1 长度异常: {len(hex_sha1)} (期望 {_HEX_SHA1_LEN})"
        )

    return MedusaEnvelopePartial(
        builder_sha1=builder_sha1,
        byte18=byte18,
        byte19=byte19,
        hex_sha1=hex_sha1,
        input_data=bytes(input_data) if isinstance(input_data, bytearray) else input_data,
        local_ts_sec=local_ts_sec,
        lag=lag,
    )


def xmxor(data, key):
    """Medusa专用XOR混淆"""
    data = xmxor_two(data, key)
    last_flag = data[-1] ^ data[-2]
    data0 = data[0]
    data[0] = (~last_flag + data[0]) & 0xff
    data[1] = ((data[0] ^ data[-1] ^ 254) + data[1]) & 0xff
    data[2] = (data[2] + ((last_flag - data0) ^ rl8(data[1], 3) ^ 2)) & 0xff
    for i in range(len(data) - 4):
        temp = (rl8(data[i + 2], 3)) ^ data[i + 1] ^ (i + 3)
        data[i + 3] = (~temp + data[i + 3]) & 0xff
    data[-1] ^= data[-2]
    sum = 0
    for i in range(len(data) - 1):
        sum += int(data[i + 1])
    data[0] = ((data[0] ^ data[1]) + sum) & 0xff
    return data


def xmxor_two(data, key):
    """Medusa XOR第一层"""
    enc_data = bytearray(len(data))
    for i in range(len(data)):
        index = (i * 4) & 28
        d0 = key[index]
        d1 = key[index + 1]
        d2 = (rl8(data[i], 4) + d0) ^ d1
        d2 = ~d2
        d2 = (rl8(d2 & 0xff, 3)) & 0xff
        d2 += d1
        d2 = (d2 & 0xff) ^ d0
        enc_data[-i - 1] = ~d2 & 0xff
    return enc_data


# ---------------------------------------------------------------------------
# v39 xmxor 逆向 (P9aa A1: 整合 P9z Z1 验证, score=178)
# ---------------------------------------------------------------------------
# P9z Z1 已确认 (scatter 移除后 score=178, 含完整 protobuf):
#   - xmxor key 派生: key = SM3(sign_key + hash_rand_le4 + sign_key)  (32B)
#     (由 get_key_hash 实现, 推翻 P9y Y2 的 "SHA1 XOR sign_key" 假设)
#   - sign_key = 8ebdfa3806ecc5cee79423e6029ed82540bc2218bb7eaef71cb691f7aa8aa2f5
#   - random_mask (18B, sample 0): 1ad55a78ffccd37f8a045caba8b64432cb16
#   - 移除 scatter + native noise 后, inv_xmxor 输出完整 protobuf
#   - proto 含: v39 magic, "1128", "v04.10.01", "ml-android", "1588093228"
# ---------------------------------------------------------------------------

V39_SIGN_KEY = bytes.fromhex(
    "8ebdfa3806ecc5cee79423e6029ed825"
    "40bc2218bb7eaef71cb691f7aa8aa2f5"
)

# v39 envelope 字段长度
V39_ENVELOPE_LEN = 272
V39_MIDDLE_LEN = 224
V39_PROTO_LEN = 216

# v39 magic (envelope version_or 后 16B, 也是 protobuf field1 的值)
V39_MAGIC = bytes.fromhex("6b9a2b2a429baf9181ca026ac236a4fe")


def inv_xmxor_two(enc_data, key):
    """逆 xmxor_two: 还原原始 proto_data (P9z Z1 验证).

    正向 (xmxor_two):
      enc_data[-i-1] = ~d2 & 0xff
      d0 = key[index], d1 = key[index+1], index = (i*4) & 28
      d2 = (rl8(data[i], 4) + d0) ^ d1
      d2 = ~d2
      d2 = rl8(d2 & 0xff, 3) & 0xff
      d2 += d1
      d2 = (d2 & 0xff) ^ d0

    逆向: 已知 enc_data[-i-1], 求 data[i] (逐步骤取逆).
    """
    n = len(enc_data)
    data = bytearray(n)
    for i in range(n):
        index = (i * 4) & 28
        d0 = key[index]
        d1 = key[index + 1]
        d2 = (~enc_data[-i - 1]) & 0xff  # 逆 ~
        d2 = d2 ^ d0                       # 逆 ^ d0
        d2 = (d2 - d1) & 0xff             # 逆 + d1
        d2 = rl8(d2, 5) & 0xff            # 逆 rl8(.,3) (3+5=8)
        d2 = (~d2) & 0xff                 # 逆 ~
        d2 = d2 ^ d1                       # 逆 ^ d1
        orig = rl8((d2 - d0) & 0xff, 4)   # 逆 + d0 和 rl8(.,4) (自逆)
        data[i] = orig
    return data


def inv_xmxor(enc_data, key):
    """完整逆 xmxor (步骤 2-9 的逆 + 逆 xmxor_two).

    正向步骤 (xmxor):
      1. data = xmxor_two(data, key)
      2. last_flag = data[-1] ^ data[-2]
      3. data0 = data[0]  (保存)
      4. data[0] = (~last_flag + data[0]) & 0xff
      5. data[1] = ((data[0] ^ data[-1] ^ 254) + data[1]) & 0xff
      6. data[2] = (data[2] + ((last_flag - data0) ^ rl8(data[1], 3) ^ 2)) & 0xff
      7. for i in range(n-4): data[i+3] = (~temp + data[i+3]) & 0xff
         temp = rl8(data[i+2], 3) ^ data[i+1] ^ (i+3)
      8. data[-1] ^= data[-2]
      9. data[0] = ((data[0] ^ data[1]) + sum(data[1:])) & 0xff
    """
    data = bytearray(enc_data)
    n = len(data)
    # 逆步骤 9: data[0]_step8 = ((data[0] - sum) & 0xff) ^ data[1]
    sum_val = sum(data[1:]) & 0xff
    data[0] = ((data[0] - sum_val) & 0xff) ^ data[1]
    # 逆步骤 8
    data[-1] ^= data[-2]
    # 逆步骤 7 (从后往前)
    for i in range(n - 5, -1, -1):
        temp = (rl8(data[i + 2], 3) ^ data[i + 1] ^ (i + 3)) & 0xff
        data[i + 3] = (data[i + 3] + temp + 1) & 0xff
    # last_flag (步骤 2): data[-1] 未被步骤 4-7 修改, data[-2] 已还原
    last_flag = data[-1] ^ data[-2]
    # 保存步骤 4 后的 data[0] 用于步骤 5 逆
    data0_step4 = data[0]
    # 逆步骤 4: data[0]_orig = (data[0] + last_flag + 1) & 0xff
    data0_orig = (data0_step4 + last_flag + 1) & 0xff
    # 保存步骤 5 后的 data[1] 用于步骤 6 逆
    data1_step5 = data[1]
    # 逆步骤 5
    data[1] = (data[1] - (data0_step4 ^ data[-1] ^ 254)) & 0xff
    # 逆步骤 6
    data[2] = (data[2] - ((last_flag - data0_orig) ^ rl8(data1_step5, 3) ^ 2)) & 0xff
    # 还原 data[0] 到步骤 1 后的值
    data[0] = data0_orig
    # 逆 xmxor_two
    return inv_xmxor_two(data, key)


def parse_v39_envelope(raw):
    """解析 v39 envelope (272B) 为字段 dict.

    字段布局:
      [0:20]   version_or (5x 4B LE, = khronos XOR version_magic)
      [20:22]  hash_rand[:2]
      [22:24]  flags = 0x0D00 LE
      [24:37]  header_extension (13B random)
      [37]     fix_byte (0x35 / 0xb5)
      [38:42]  xm_rand (4B LE)
      [42:46]  check_bit (4B LE)
      [46:270] middle (224B = prefix[8] + xmxor(proto[216], key), reversed,
                      XOR seed, scatter, noise)
      [270:272] hash_rand[2:]
    """
    if len(raw) != V39_ENVELOPE_LEN:
        raise ValueError(
            f"v39 envelope must be {V39_ENVELOPE_LEN} bytes, got {len(raw)}"
        )
    middle = raw[46:len(raw) - 2]
    hash_rand_first2 = raw[20:22]
    hash_rand_tail2 = raw[len(raw) - 2:len(raw)]
    hash_rand_full = int.from_bytes(hash_rand_first2 + hash_rand_tail2, "little")
    return {
        "version_or": raw[0:20],
        "hash_rand_first2": hash_rand_first2,
        "flags": int.from_bytes(raw[22:24], "little"),
        "header_extension": raw[24:37],
        "fix_byte": raw[37],
        "xm_rand": int.from_bytes(raw[38:42], "little"),
        "check_bit": int.from_bytes(raw[42:46], "little"),
        "middle": middle,
        "hash_rand_tail2": hash_rand_tail2,
        "hash_rand_full": hash_rand_full,
        "middle_len": len(middle),
    }


def reverse_v39_middle_outer(middle, seed, random_mask):
    """完整逆向 v39 middle 外层变换 (un-noise + un-scatter + un-seed + un-reverse + 去 prefix).

    forward 方向 (medusa_v39_middle):
      1. data = prefix(8) + xmxor(proto, key)   # 224 bytes
      2. data.reverse()
      3. data_rev[i] ^= seed[~i & 3]             # XOR seed
      4. data_rev[i] ^= scatter[i] for i in [0,144)  # scatter (1-bit/byte)
      5. data_rev[i] ^= noise[i]                 # native noise

    reverse 方向 (本函数):
      1. data_rev[i] ^= noise[i]                 # un-noise
      2. data_rev[i] ^= scatter[i] for i in [0,144)  # un-scatter
      3. data_rev[i] ^= seed[~i & 3]             # un-seed
      4. data.reverse()                          # un-reverse
      5. enc_proto = data[8:]                     # remove prefix

    Args:
        middle: 224 字节 envelope middle 段.
        seed: 4 字节 seed (由 get_key_hash 派生, 只依赖 hash_rand).
        random_mask: 18 字节 scatter mask (必须由调用方提供, fail-closed).

    Returns:
      干净的 enc_proto (216 字节, 无 scatter/noise, 可直接 inv_xmxor).

    Raises:
        FailClosedError: random_mask 长度不是 18 字节.
    """
    if len(random_mask) != 18:
        raise _resolve_fail_closed_error()(
            f"random_mask must be 18 bytes (v39 scatter mask), "
            f"got {len(random_mask)}"
        )
    data = bytearray(middle)
    # 1. un-noise (native noise: proto_length + 8 bytes, noise[proto_length+6]=0x04)
    noise = medusa_v39_native_noise(V39_PROTO_LEN)
    for i in range(len(data)):
        data[i] ^= noise[i]
    # 2. un-scatter (144 bytes expanded from 18-byte random_mask)
    expanded = expand_v39_random_mask(random_mask)
    for i in range(min(144, len(data))):
        data[i] ^= expanded[i]
    # 3. un-seed
    for i in range(len(data)):
        data[i] ^= seed[~i & 3]
    # 4. un-reverse
    data.reverse()
    # 5. remove prefix (8 bytes)
    return bytes(data[8:])


def decrypt_v39_xmxor(envelope_raw, random_mask, sign_key=None):
    """端到端解密 v39 X-Medusa envelope 的 xmxor 层 (P9aa A1).

    完整解密流程:
      1. 解析 envelope (272B) → middle (224B) + hash_rand (4B LE)
      2. 派生 key + seed: key = SM3(sign_key + hash_rand_le4 + sign_key)  (32B)
         (由 get_key_hash 实现, 推翻 P9y Y2 的 "SHA1 XOR sign_key" 假设)
      3. 逆向 middle 外层: un-noise + un-scatter + un-seed + un-reverse + 去 prefix
      4. inv_xmxor(enc_proto, key) → protobuf (216B)

    Args:
        envelope_raw: 272 字节 v39 envelope (base64 解码后).
        random_mask: 18 字节 scatter mask (必须由调用方提供, fail-closed).
        sign_key: 32 字节 sign key (默认 V39_SIGN_KEY).

    Returns:
        解密后的 protobuf bytes (216 字节), 含 v39 magic + "1128" +
        "v04.10.01" + "ml-android" + "1588093228".

    Raises:
        FailClosedError: random_mask 缺失, 或解密输出不含 v39 magic
                        (表示 key/mask 错误, 不允许 silent default 或 replay).
    """
    if sign_key is None:
        sign_key = V39_SIGN_KEY
    if random_mask is None:
        raise _resolve_fail_closed_error()(
            "random_mask 不可用 — v39 scatter mask 必须由调用方提供 (fail-closed)"
        )
    # 1. 解析 envelope
    env = parse_v39_envelope(envelope_raw)
    middle = env["middle"]
    hash_rand = env["hash_rand_full"]
    # 2. 派生 key + seed (key = SM3(sign_key + hash_rand_le4 + sign_key))
    key, seed = get_key_hash(sign_key, hash_rand)
    # 3. 逆向 middle 外层 (un-noise + un-scatter + un-seed + un-reverse + 去 prefix)
    enc_proto = reverse_v39_middle_outer(middle, seed, random_mask)
    # 4. inv_xmxor
    proto = bytes(inv_xmxor(enc_proto, key))
    # 5. fail-closed 验证: 必须含 v39 magic
    if V39_MAGIC not in proto:
        raise _resolve_fail_closed_error()(
            f"v39 xmxor 解密失败 — proto 不含 v39 magic "
            f"(key={key.hex()[:8]}..., 可能 sign_key/random_mask 错误)"
        )
    return proto


V39_MASK_BIT_ORDER = (5, 1, 6, 2, 0, 3, 4, 7)

# Mill (8-aligned proto) middle prefix: byte[1] = 0x02.
# Mill-less native appends xmxor onto 8 zero bytes; using 00020000 there
# leaves a dirty tail at proto_len+6 (observed 0x02 on proto 271).
V39_MIDDLE_PREFIX = bytes.fromhex("0002000000000000")
V39_MIDDLE_PREFIX_MILLLESS = bytes(8)


def medusa_v39_prefix(proto_length):
    """Select the 8-byte middle prefix for mill vs mill-less WRAP."""
    if proto_length and proto_length % 8 == 0:
        return V39_MIDDLE_PREFIX
    return V39_MIDDLE_PREFIX_MILLLESS


def expand_v39_random_mask(random_mask):
    """Expand v39's 18 random bytes into 144 single-bit byte masks."""
    if len(random_mask) != 18:
        raise ValueError("v39 random_mask must contain exactly 18 bytes")
    expanded = bytearray(144)
    for index in range(144):
        source_bit = (random_mask[index >> 3] >> (index & 7)) & 1
        expanded[index] = source_bit << V39_MASK_BIT_ORDER[index & 7]
    return expanded


# Perseus scatter source-bit map, reused by mill-less Medusa at offset-0.
# output_bit -> source_bit for bits 0..6; bit 7 is next_source.bit5 except
# the last group, which retains the old payload bit (mask bit7 stays 0).
# v34 WRAP AES slot constants observed at 0x2be114 slot10/slot11.
V34_WRAP_KEY = bytes.fromhex("f1593376766ea98d34f31b057a9d5be4")
V34_WRAP_IV = bytes.fromhex("1fe109a4125283f418de9e051a969e12")
WRAP_EPROFILE_SELECTOR = 2


def _read_proto_varint(buf, index):
    value = 0
    shift = 0
    n = len(buf)
    while index < n:
        byte = buf[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, index
        shift += 7
        if shift > 63:
            break
    return None, index


def proto_bytes_field(proto_data, number):
    """Return the first length-delimited protobuf field with this number."""
    index = 0
    data = memoryview(proto_data)
    n = len(data)
    while index < n:
        key, index = _read_proto_varint(data, index)
        if key is None:
            break
        field_number, wire_type = key >> 3, key & 7
        if wire_type == 0:
            _, index = _read_proto_varint(data, index)
        elif wire_type == 1:
            index += 8
        elif wire_type == 2:
            length, index = _read_proto_varint(data, index)
            if length is None:
                break
            blob = bytes(data[index:index + length])
            index += length
            if field_number == number:
                return blob
        elif wire_type == 5:
            index += 4
        else:
            break
    return b""


def wrap_encrypt_32(plaintext19, key=V34_WRAP_KEY, iv=V34_WRAP_IV,
                    selector=WRAP_EPROFILE_SELECTOR):
    """19B CSPRNG -> 32B mill-less WRAP ciphertext.

    Live 0x2be114 mill-less WRAP is the dumped w26/w109 mill (PKCS7 + CBC-IV
    + mill SPN), not scatter E_profile.  Envelope salts are slices of this
    block: source18=ct[1:19], header_extension=ct[19:32].
    """
    del selector
    import sys
    from pathlib import Path
    eng = str(Path(__file__).resolve().parent)
    if eng not in sys.path:
        sys.path.insert(0, eng)
    from _wrap_encrypt_mill import wrap_encrypt_32 as _mill_wrap
    return _mill_wrap(plaintext19, key=key, iv=iv)


V39_SCATTER_SOURCE_BITS = (7, 3, 6, 4, 1, 2, 0)


def generate_medusa_v39_scatter_mask(source18, pre_scatter):
    """Build the packed 18B Medusa scatter mask from an 18B WRAP source.

    Live mill-less WRAP stores a 32B slot as 19B||header_ext13; the 18B
    source is bytes [1:19] of that 19B.  The bit map matches Perseus
    generate_scatter_mask, but the payload index is offset-0 and the last
    group's output bit 7 is left unset (retain).
    """
    if len(source18) != 18:
        raise ValueError("v39 Medusa scatter source must contain exactly 18 bytes")
    if len(pre_scatter) < 144:
        raise ValueError("pre-scatter payload is too short for an 18B mask")
    mask = bytearray(18)
    for group in range(18):
        for output_bit, source_bit in enumerate(V39_SCATTER_SOURCE_BITS):
            old = (pre_scatter[group * 8 + output_bit] >> V39_MASK_BIT_ORDER[output_bit]) & 1
            desired = (source18[group] >> source_bit) & 1
            if old ^ desired:
                mask[group] |= 1 << output_bit
        if group + 1 < 18:
            output_bit = 7
            old = (pre_scatter[group * 8 + output_bit] >> V39_MASK_BIT_ORDER[output_bit]) & 1
            desired = (source18[group + 1] >> 5) & 1
            if old ^ desired:
                mask[group] |= 1 << output_bit
    return bytes(mask)


def apply_v39_ct0_to_prefix(xm_rand, check_bit, ct0, ct1=0):
    """Embed WRAP CT[0] into the 8-byte xm||cb prefix; bit5 of CT[0] is fix mode.

    mill6 hashes the pre-scatter prefix (fix 0x35 + xm + cb).  The wire copies
    scatter CT[0] into those 8 bytes with the same SOURCE_BITS/MASK_BIT_ORDER
    map as a single 8-byte group (last bit retains, or holds CT[1].bit5).
    Wire fix_byte_mode is CT[0] bit 5 (0x35 vs 0xb5).
    """
    pre = bytearray(xm_rand.to_bytes(4, "little") + check_bit.to_bytes(4, "little"))
    source = ct0 & 0xFF
    for output_bit, source_bit in enumerate(V39_SCATTER_SOURCE_BITS):
        old = (pre[output_bit] >> V39_MASK_BIT_ORDER[output_bit]) & 1
        desired = (source >> source_bit) & 1
        if old ^ desired:
            pre[output_bit] ^= 1 << V39_MASK_BIT_ORDER[output_bit]
    old = (pre[7] >> V39_MASK_BIT_ORDER[7]) & 1
    desired = (ct1 >> 5) & 1
    if old ^ desired:
        pre[7] ^= 1 << V39_MASK_BIT_ORDER[7]
    xm_wire = int.from_bytes(pre[:4], "little")
    cb_wire = int.from_bytes(pre[4:], "little")
    fix_mode = (source >> 5) & 1
    return xm_wire, cb_wire, fix_mode


def medusa_v39_middle(proto_data, key, seed, noise_mask=None,
                      random_mask=None, prefix=V39_MIDDLE_PREFIX):
    """Build the v39 middle section without invoking the native library.

    v39 prefixes the transformed protobuf with an 8-byte header whose second
    byte is the version-specific constant 0x02 (observed as
    ``00 02 00 00 00 00 00 00`` across all captured X-Medusa samples).  The
    native implementation optionally toggles one bit per byte afterwards;
    accepting that mask keeps the deterministic transform independently
    testable and permits byte-exact replay of captured requests.
    """
    data = bytearray(prefix + xmxor(bytearray(proto_data), key))
    data.reverse()
    for index in range(len(data)):
        data[index] ^= seed[~index & 3]
    if random_mask is not None:
        expanded = expand_v39_random_mask(random_mask)
        for index, value in enumerate(expanded[:len(data)]):
            data[index] ^= value
    if noise_mask is not None:
        if len(noise_mask) != len(data):
            raise ValueError("noise_mask length must match the Medusa middle")
        for index, value in enumerate(noise_mask):
            data[index] ^= value
    return data


def medusa_v39_native_noise(proto_length):
    """Model the VM's final scatter step for 8-byte-aligned protobufs."""
    noise = bytearray(proto_length + 8)
    if proto_length and proto_length % 8 == 0:
        noise[proto_length + 6] = 0x04
    return bytes(noise)


def gen_medusa_v39_body(proto_data, query_sm3, body_hash, hash_rand,
                        xm_rand, random_mask=None, check_bit=None,
                        fix_byte=0x35, noise_mask=None, fix_byte_mode=0,
                        scatter_source=None):
    """Build the complete unencrypted v39 body used after the 37-byte header.

    fix_byte_mode selects the high-bit mode of the fix byte:
      0 -> fix_byte  (default, 0x35)
      1 -> fix_byte ^ 0x80  (0x35 -> 0xb5)
    The mode selector's trigger condition is not yet recovered; it is
    parameterized here so byte-exact replay can choose either value.

    scatter_source, when given, is the 18-byte WRAP ciphertext slice
    ``ct[1:19]``.  The packed mask is then derived from the pre-scatter
    payload instead of being sampled independently.
    """
    sign_key = bytes.fromhex(
        "8ebdfa3806ecc5cee79423e6029ed825"
        "40bc2218bb7eaef71cb691f7aa8aa2f5"
    )
    key, seed = get_key_hash(sign_key, hash_rand)
    native_noise = medusa_v39_native_noise(len(proto_data))
    if noise_mask is not None:
        if len(noise_mask) != len(native_noise):
            raise ValueError("noise_mask length must match the Medusa middle")
        native_noise = bytes(a ^ b for a, b in zip(native_noise, noise_mask))
    prefix = medusa_v39_prefix(len(proto_data))
    pre_scatter = medusa_v39_middle(
        proto_data, key, seed, random_mask=None,
        noise_mask=native_noise, prefix=prefix,
    )
    if scatter_source is not None:
        random_mask = generate_medusa_v39_scatter_mask(scatter_source, pre_scatter)
    elif random_mask is None:
        random_mask = os.urandom(18)
    middle = medusa_v39_middle(
        proto_data, key, seed, random_mask=random_mask,
        noise_mask=native_noise, prefix=prefix,
    )
    if check_bit is None:
        check_bit = (query_sm3[0] & 63) << 14
        check_bit |= 0x18000001
        check_bit |= (body_hash[0] & 63) << 8
    if not 0 <= fix_byte <= 0xff:
        raise ValueError("Medusa fix byte must fit in one byte")
    if fix_byte_mode not in (0, 1):
        raise ValueError("fix_byte_mode must be 0 or 1")
    effective_fix_byte = fix_byte ^ (0x80 if fix_byte_mode else 0x00)
    return (bytes((effective_fix_byte,)) + xm_rand.to_bytes(4, "little")
            + check_bit.to_bytes(4, "little") + middle
            + hash_rand.to_bytes(4, "little")[2:])


def mill6_pre_scatter_src(proto_data, hash_rand, xm_rand, check_bit, fix_byte=0x35):
    """Build mill6's 290B pre-scatter WRAP body (fix+xm+cb+middle+hr[2:])."""
    key, seed = get_key_hash(V39_SIGN_KEY, hash_rand)
    middle = medusa_v39_middle(
        proto_data, key, seed, noise_mask=None, random_mask=None,
        prefix=V39_MIDDLE_PREFIX_MILLLESS,
    )
    return (
        bytes((fix_byte & 0xFF,))
        + xm_rand.to_bytes(4, "little")
        + check_bit.to_bytes(4, "little")
        + bytes(middle)
        + hash_rand.to_bytes(4, "little")[2:]
    )


def mill6_wrap_ct32(proto_data, hash_rand, xm_rand, check_bit, fix_byte=0x35):
    """纯算 mill6(src(proto,hr,xm,cb)) -> 19B PT -> WRAP mill 32B CT."""
    import sys
    from pathlib import Path
    eng = str(Path(__file__).resolve().parent)
    if eng not in sys.path:
        sys.path.insert(0, eng)
    from _wrap_pt19_mill6 import mill6_pt19
    src = mill6_pre_scatter_src(proto_data, hash_rand, xm_rand, check_bit, fix_byte)
    return wrap_encrypt_32(mill6_pt19(src))


def gen_medusa_v39_raw(proto_data, khronos, query_sm3, body_hash,
                       hash_rand=None, xm_rand=None, random_mask=None,
                       header_extension=None, check_bit=None,
                       fix_byte=0x35, noise_mask=None, fix_byte_mode=0,
                       scatter_source=None):
    """Generate the complete binary X-Medusa value for Douyin v39.

    The 13-byte header extension and the 18-byte scatter mask are per-request
    salts. They are generated locally unless supplied for byte-exact replay.
    When scatter_source is provided it wins over random_mask and is packed
    with generate_medusa_v39_scatter_mask against the pre-scatter payload.

    Default mill-less salts come from mill6(pre-scatter body) -> WRAP mill CT:
    scatter_source=ct[1:19], header_extension=ct[19:32].  CT[0] is embedded
    in the wire fix/xm/cb prefix (apply_v39_ct0_to_prefix).  hash_rand is
    bound to the protobuf; pass the proto's hash_rand when swapping WRAP
    on an existing ticket.
    """
    hash_rand = (int.from_bytes(os.urandom(4), "little")
                 if hash_rand is None else hash_rand)
    xm_rand = (int.from_bytes(os.urandom(4), "little")
               if xm_rand is None else xm_rand)
    if check_bit is None:
        check_bit = ((query_sm3[0] & 63) << 14) | 0x18000001 | ((body_hash[0] & 63) << 8)
    mill6_fix = fix_byte & 0x7F
    if scatter_source is None and header_extension is None and random_mask is None:
        wrap_ct = mill6_wrap_ct32(
            proto_data, hash_rand, xm_rand, check_bit, mill6_fix,
        )
        scatter_source = wrap_ct[1:19]
        header_extension = wrap_ct[19:32]
        xm_rand, check_bit, fix_byte_mode = apply_v39_ct0_to_prefix(
            xm_rand, check_bit, wrap_ct[0], wrap_ct[1],
        )
    if scatter_source is None and random_mask is None:
        random_mask = os.urandom(18)
    header_extension = (os.urandom(13) if header_extension is None
                        else header_extension)
    if len(header_extension) != 13:
        raise ValueError("v39 header_extension must contain exactly 13 bytes")

    version = bytes.fromhex(
        "070000006b9a2b2a429baf9181ca026ac236a4fe"
    )
    version_or = b"".join(
        (int.from_bytes(version[index:index + 4], "little") ^ khronos)
        .to_bytes(4, "little")
        for index in range(0, 20, 4)
    )
    body = gen_medusa_v39_body(
        proto_data, query_sm3, body_hash, hash_rand, xm_rand,
        random_mask=random_mask, check_bit=check_bit,
        fix_byte=fix_byte, noise_mask=noise_mask,
        fix_byte_mode=fix_byte_mode, scatter_source=scatter_source,
    )
    return (version_or + hash_rand.to_bytes(4, "little")[:2]
            + (0x0D00).to_bytes(2, "little") + header_extension + body)


def gen_medusa_v39_base64(*args, **kwargs):
    return base64.b64encode(gen_medusa_v39_raw(*args, **kwargs)).decode()


def gen_medusa_proto_v39(*, rand, khronos, device_id, app_version,
                         query_body_ts_hash, query_sm3, request,
                         sec_device_token, unknown28=22,
                         unknown29=3971697493, lanusk_hash=b"",
                         query_body_hash_sm3=b"", call_type=312,
                         time2=None):
    """Serialize the compact protobuf used by Douyin v39's 0x3000001 path.

    Phone mill-less search proto is ~269B: 25-char f16, f17=time, f18 20B
    lanusk (F18 VM, not MD5||MD5[:4]), f19 32B mill-less nonce, call_type 369.
    Embedding 151B x-tt-dt as f16 inflates WRAP 325→383 and sharks.
    """
    message = Medusa(
        magic=bytes.fromhex("6b9a2b2a429baf9181ca026ac236a4fe"),
        version=7,
        rand=rand,
        ms_app_id="1128",
        device_id=str(device_id),
        license_id="1588093228",
        app_version=app_version,
        sdk_version_str="v04.10.01-ml-android",
        sdk_version=67764480,
        xg_seed_bytes=bytes(8),
        time=khronos,
        query_body_ts_hash=bytes(query_body_ts_hash),
        query_sm3=bytes(query_sm3[:6]),
        request=request,
        sec_device_token=sec_device_token or "",
        time2=khronos if time2 is None else int(time2),
        lanusk_hash=bytes(lanusk_hash or b""),
        query_body_hash_sm3=bytes(query_body_hash_sm3 or b""),
        psk_version="1",
        call_type=call_type,
        unknown28=unknown28,
        unknown29=unknown29,
    )
    return bytes(message)


__all__ = [
    "V39_MASK_BIT_ORDER", "V39_SIGN_KEY", "compute_field13", "xmxor",
    "gen_medusa_proto_v39", "gen_medusa_v39_raw", "gen_medusa_v39_base64",
]

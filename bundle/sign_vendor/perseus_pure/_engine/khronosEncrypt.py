# -*- encoding: utf-8 -*-
"""khronosEncrypt.py — X-Khronos签名 (时间戳,秒级)"""


def encrypt_khronos(ts: int = None) -> str:
    """
    生成 X-Khronos.

    Args:
        ts: 时间戳(秒), None=当前时间

    Returns:
        10位字符串时间戳
    """
    import time
    return str(ts if ts is not None else int(time.time()))

"""perseus_pure — 抖音 v39 X-Perseus 纯算独立包(从 qishen_pure 抽取).

用法:
    from perseus_pure import PerseusSigner
    sig = PerseusSigner(device_id="692017604375395", app_version="39.3.0")
    x_perseus = sig.get_value(url="https://aweme.snssdk.com/aweme/v1/feed/?...", body=b"", timestamp=None)
"""
from .perseus import PerseusSigner
__all__ = ["PerseusSigner"]

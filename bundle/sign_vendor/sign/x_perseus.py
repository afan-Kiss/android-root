# -*- coding: utf-8 -*-
"""39.3 X-Perseus：本目录旁的 perseus_pure。"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from perseus_pure import PerseusSigner

_APP_VERSION = "39.3.0"
_signers: dict[str, PerseusSigner] = {}


def _signer(device_id: str) -> PerseusSigner:
    did = str(device_id or "0")
    inst = _signers.get(did)
    if inst is None:
        inst = PerseusSigner(device_id=did, app_version=_APP_VERSION)
        _signers[did] = inst
    return inst


class Perseus:
    def get_value(
        self,
        timestamp: str,
        url: str = "",
        body="",
        device_id: str = "",
        version_name: str = "",
    ) -> str:
        _ = version_name
        raw = body if isinstance(body, (bytes, bytearray)) else str(body or "").encode("utf-8")
        ts = int(timestamp) if timestamp else None
        return _signer(device_id).get_value(
            url=url or "https://aweme.snssdk.com/",
            body=bytes(raw),
            timestamp=ts,
        )

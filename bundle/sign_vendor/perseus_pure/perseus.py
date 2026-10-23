# -*- coding: utf-8 -*-
"""perseus_pure.perseus — X-Perseus 纯算干净入口.

对外只暴露 Perseus 一个神:给 url/body/timestamp,纯算直出 X-Perseus 头(base64 str).
内部复用从 qishen_pure 抽取的 QishenPureEngine.generate_perseus 完整链路
(256-handler VM + f13/f18/f19 遥测 + scatter + 自定义 base64).
"""
from __future__ import annotations

import time

from .api import QishenPureEngine, DeviceProfile, RequestInput


class PerseusSigner:
    """抖音 v39 X-Perseus 纯算签名器.

    Parameters
    ----------
    device_id : str
        设备 did.
    app_version : str
        app 版本, 默认 "39.3.0".
    """

    def __init__(self, device_id: str, app_version: str = "39.3.0") -> None:
        self._device = DeviceProfile(device_id=device_id, app_version=app_version)
        self._engine = QishenPureEngine(self._device)

    def get_value(
        self,
        url: str,
        body: bytes = b"",
        timestamp: int | None = None,
    ) -> str:
        """纯算生成 X-Perseus 头.

        Parameters
        ----------
        url : str
            完整请求 URL(带 query).
        body : bytes
            请求体, GET 传 b"".
        timestamp : int | None
            秒级时间戳, None 则取当前时间.

        Returns
        -------
        str
            X-Perseus 头值(自定义 base64).
        """
        ts = int(time.time()) if timestamp is None else int(timestamp)
        req = RequestInput(url=url, body=body or b"", timestamp=ts)
        return self._engine.generate_perseus(req)


__all__ = ["PerseusSigner", "QishenPureEngine", "DeviceProfile", "RequestInput"]

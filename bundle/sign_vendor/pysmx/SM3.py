# -*- coding: utf-8 -*-
# pysmx shim: PyPI 的 pysmx 是 SourceMod VM（命名冲突），这里复用包内 _sm3_impl 的 SM3 实现
import sys, os

_PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 39.3_login_sms 根
_ENG = os.path.join(_PKG, "perseus_pure", "_engine")
if _ENG not in sys.path:
    sys.path.insert(0, _ENG)

from _sm3_impl import SM3  # noqa: E402,F401

"""Pure Python X-Gorgon + X-Argus signing for webcast."""
from __future__ import annotations
import os, sys, time
from pathlib import Path
from urllib.parse import urlparse
_VENDOR = Path(os.environ.get("PURE_SIGN_VENDOR", ""))
if not _VENDOR.is_dir():
    _VENDOR = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign")) / "tmp" / "sign-pack-original" / "dy_unified" / "vendor"
if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))
from sign.x_argus import Argus
from sign.x_gorgon import get_xgorgon
_argus = Argus()

def sign_url(url: str, body: str = "", cookie: str = "", device_id: str = "", version_name: str = "40.7.0") -> dict:
    ts = int(time.time())
    query = urlparse(url).query
    did = device_id or ""
    for part in query.split("&"):
        if part.startswith("device_id=") and not did:
            did = part.split("=", 1)[1]
    return {
        "x-gorgon": get_xgorgon(ts, url, body, cookie),
        "x-khronos": str(ts),
        "x-argus": _argus.get_value(str(ts), aid="1128", device_id=did, version_name=version_name, stub="", query=query),
        "x-ss-req-ticket": str(ts * 1000),
    }


def sign_url_full(
    url: str,
    body: str = "",
    cookie: str = "",
    device_id: str = "",
    device_token: str = "",
    version_name: str = "40.7.0",
) -> dict:
    """Alias for sign_url (full six-god headers not required for warmup/enter)."""
    return sign_url(url, body=body, cookie=cookie, device_id=device_id, version_name=version_name)
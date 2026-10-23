import hashlib
import json
from urllib.parse import parse_qs, urlencode, urlparse


def parse_url_params(url: str) -> dict:
    params = {}
    for key, value in parse_qs(urlparse(url).query).items():
        params[key] = value[0]
    return params


def url_query(url: str) -> str:
    return url.split("?", 1)[1] if "?" in url else ""


def md5hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def data_md5_upper(data, data_type: str = None) -> str:
    if not data:
        return ""

    md5 = hashlib.md5()
    if isinstance(data, str):
        md5.update(data.encode("utf-8"))
    elif isinstance(data, bytes):
        md5.update(data)
    elif data_type == "application/json; charset=UTF-8":
        md5.update(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    else:
        md5.update(urlencode(data).encode("utf-8"))
    return md5.hexdigest().upper()


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def device_context_from_params(params: dict) -> dict:
    device_type = params.get("device_type", "")
    device_brand = params.get("device_brand", "")
    return {
        "device_id": params.get("device_id", params.get("did", "")),
        "iid": params.get("iid", ""),
        "os_version": params.get("os_version", ""),
        "version_name": params.get("version_name", ""),
        "device_model": device_type,
        "device_type": device_type,
        "device_brand": device_brand,
        "device_manufacturer": device_brand,
    }

"""华生代理 + 通用代理解析，供注册/采集使用。"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_PROXY_API = (
    "https://getip.huashengdaili.com/servers.php?"
    "session=U94feb8410923121918--483daffff81cf261824e9615375156fa"
    "&time=1&count=1&type=text&pw=no&protocol=http&separator=1&iptype=tunnel&format=null&dev=web"
)

PROXY_API = os.environ.get("COLLECT_PROXY_API", DEFAULT_PROXY_API)


def parse_proxy(line: str) -> dict[str, str] | None:
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("{"):
        try:
            data = json.loads(line)
            if data.get("status") not in (None, 0, 200):
                raise RuntimeError(data.get("detail") or data.get("msg") or line[:200])
        except json.JSONDecodeError:
            pass
        else:
            return None
    if "://" in line:
        url = line
    elif line.count(":") == 3:
        host, port, user, pwd = line.split(":", 3)
        url = "http://%s:%s@%s:%s" % (user, pwd, host, port)
    elif line.count(":") == 1:
        host, port = line.split(":", 1)
        url = "http://%s:%s" % (host, port)
    else:
        return None
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port:
        return None
    return {"http": url, "https": url}


def load_proxy_file(path: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        p = parse_proxy(line)
        if p:
            out.append(p)
    return out


def fetch_proxy(api_url: str | None = None, timeout: int = 15) -> dict[str, str] | None:
    import requests

    url = (api_url or PROXY_API or "").strip()
    if not url:
        return None
    try:
        r = requests.get(url, timeout=timeout)
        text = (r.text or "").strip()
        if not text:
            return None
        if text.startswith("{"):
            data = json.loads(text)
            if data.get("status") not in (None, 0, 200):
                return None
        line = text.splitlines()[0].strip()
        return parse_proxy(line)
    except Exception:
        return None

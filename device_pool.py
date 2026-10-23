"""Device pool: only devices that pass android webcast enter."""
from __future__ import annotations
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))
DEFAULT_POOL = ROOT / "tmp" / "device_pool.json"

def load_pool(path: str | Path = DEFAULT_POOL) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        rows = json.loads(p.read_text(encoding="utf-8"))
        return rows if isinstance(rows, list) else []
    except Exception:
        return []

def save_pool(rows: list[dict], path: str | Path = DEFAULT_POOL) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

def profile_entry(profile: dict) -> dict:
    return {
        "device_id": str(profile.get("deviceId") or ""),
        "install_id": str(profile.get("installId") or ""),
        "openudid": str(profile.get("openudid") or profile.get("androidId") or ""),
        "cdid": str(profile.get("cdid") or ""),
        "device_token": "",
        "verified_enter": True,
        "source": "profile",
    }

def add_device(rows: list[dict], reg: dict, verified: bool = False) -> list[dict]:
    did = str(reg.get("device_id") or "")
    if not did:
        return rows
    for row in rows:
        if str(row.get("device_id")) == did:
            return rows
    rows.append({
        "device_id": did,
        "install_id": str(reg.get("install_id") or ""),
        "openudid": str(reg.get("openudid") or ""),
        "cdid": str(reg.get("cdid") or ""),
        "device_token": reg.get("device_token") or "",
        "verified_enter": verified,
        "source": reg.get("source") or "register",
    })
    return rows
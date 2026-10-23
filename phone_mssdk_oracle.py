"""Phone MSSDK oracle: native get_token for PC-registered device_id -> hex SDI."""
from __future__ import annotations

import concurrent.futures
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"E:\douyin-android-sign")
WS = Path(r"e:\我的源码目录\安卓ROOT")
sys.path.insert(0, str(ROOT / "tools/capture-python"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(WS))

from phone_wake import ensure_douyin_running, wake_screen

import frida

ADB = ROOT / "tools/platform-tools/adb.exe"
SERIAL = "XWEEVKY9QCVKW4R4"
PKG = "com.ss.android.ugc.aweme"
SCRIPT = ROOT / "capture/frida/capture_sdi_token.js"
PATHB_SCRIPT = ROOT / "capture/frida/pathb_encrypt_calibrate.js"
SIGN_SCRIPT = ROOT / "capture/frida/spawn_sign_rpc.js"
WIRE_BIN = ROOT / "config/mssdk_wire_body.bin"


def is_trusted_sdi_token(token: str) -> bool:
    from mssdk_trust import is_trusted_sdi_token as _trusted

    return _trusted(token)


def adb(*args: str) -> str:
    p = subprocess.run(
        [str(ADB), "-s", SERIAL, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
    )
    return (p.stdout or "").strip()


def _pidof() -> int:
    out = adb("shell", "pidof", PKG)
    if not out:
        return 0
    try:
        return int(out.split()[0])
    except (ValueError, IndexError):
        return 0


def _restart_frida_server() -> None:
    from frida_root import ensure_frida_root

    ensure_frida_root()


def _profile_sdi() -> tuple[str, str]:
    try:
        prof = json.loads((ROOT / "config/device_profile.json").read_text(encoding="utf-8"))
        prefs = prof.get("mssdkPrefs") or {}
        sdi = str(prefs.get("1128-1128-sdi") or prefs.get("1128-0-sdi") or "")
        return str(prof.get("deviceId") or ""), sdi
    except Exception:
        return "", ""


def _sdi_valid_for_device(sdi: str, device_id: str, dump: dict, wire_len: int) -> bool:
    if wire_len > 600:
        return True
    if not is_trusted_sdi_token(sdi):
        return False
    prof_did, prof_sdi = _profile_sdi()
    captured = dump.get("captured") or {}
    for k, v in captured.items():
        if "ttnet" in str(k).lower() and isinstance(v, str) and is_trusted_sdi_token(v):
            return v == sdi or str(device_id) == prof_did
    if prof_sdi and sdi == prof_sdi and str(device_id) != prof_did:
        return False
    if prof_did and str(device_id) != prof_did:
        return False
    return True


def _attach_session(dev: frida.core.Device):
    wake_screen()
    pid = ensure_douyin_running(wait_sec=20.0) or _pidof()
    if pid > 0:
        for attempt in range(3):
            try:
                return dev.attach(pid), pid, "attach"
            except Exception as e:
                print(f"[oracle] attach {attempt + 1} fail: {e}")
                _restart_frida_server()
                dev = frida.get_usb_device(timeout=15)
                pid = _pidof()
                time.sleep(2)
    adb("shell", "am", "force-stop", PKG)
    time.sleep(2)
    for attempt in range(3):
        try:
            pid = dev.spawn([PKG])
            sess = dev.attach(pid)
            return sess, pid, "spawn"
        except Exception as e:
            print(f"[oracle] spawn {attempt + 1} fail: {e}")
            _restart_frida_server()
            dev = frida.get_usb_device(timeout=15)
            time.sleep(3)
    raise RuntimeError("frida attach/spawn failed")


def oracle_sdi(
    device_id: str,
    install_id: str,
    app_version: str = "40.7.0",
    spawn_wait: float = 18.0,
    use_sign_rpc: bool = False,
) -> dict:
    """Cold spawn/attach Douyin, prime MSSDK get_token for given ids. Returns {ok, sdi, wire_hex}."""
    dev = frida.get_usb_device(timeout=15)
    sess, pid, mode = _attach_session(dev)
    print(f"[oracle] {mode} pid={pid} sign_rpc={use_sign_rpc}")
    script_path = SIGN_SCRIPT if use_sign_rpc else SCRIPT
    source = frida.Compiler().build(str(script_path), project_root=str(ROOT / "capture"))
    sc = sess.create_script(source)

    early_sdi = {"token": ""}

    def on_msg(m, _):
        if m.get("type") == "error":
            print("ERR", (m.get("stack") or m.get("description") or "")[:400])
        elif m.get("type") == "send":
            p = m.get("payload") or {}
            if isinstance(p, dict) and p.get("type") == "sdi":
                tok = str(p.get("value") or "")
                if is_trusted_sdi_token(tok):
                    early_sdi["token"] = tok

    sc.on("message", on_msg)
    sc.load()
    if mode == "spawn":
        dev.resume(pid)
    wake_screen()
    boot_wait = 8.0 if mode == "attach" else (14.0 if use_sign_rpc else spawn_wait)
    time.sleep(boot_wait)
    result = {"ok": False, "sdi": "", "wire_len": 0, "wire_hex": ""}
    dump = {}
    if use_sign_rpc:
        result = sc.exports_sync.prime_mssdk_get_token(
            str(device_id), str(install_id), str(app_version)
        )
        time.sleep(6)
    else:
        time.sleep(4)
        try:
            result = sc.exports_sync.prime_sdi(str(device_id), str(install_id), str(app_version))
            print(f"[oracle] prime_sdi ok={result.get('ok')} sdi_len={len(str(result.get('sdi') or ''))}")
        except Exception as e:
            print(f"[oracle] prime_sdi skip: {e}")
            result = {"ok": False, "sdi": "", "wire_len": 0, "wire_hex": ""}
        time.sleep(2)
        dump = sc.exports_sync.dump() if hasattr(sc.exports_sync, "dump") else {}
    try:
        sess.detach()
    except Exception:
        pass
    sdi = str(result.get("sdi") or "")
    wire_hex = str(result.get("wire_hex") or "")
    wire_len = int(result.get("wire_len") or 0)
    if wire_len > 0 and wire_hex:
        try:
            raw = bytes.fromhex(wire_hex[: wire_len * 2])
            WIRE_BIN.write_bytes(raw)
        except Exception:
            pass
    if not is_trusted_sdi_token(sdi) and early_sdi.get("token"):
        sdi = early_sdi["token"]
    if not is_trusted_sdi_token(sdi):
        for k, v in (dump.get("captured") or {}).items():
            if isinstance(v, str) and is_trusted_sdi_token(v):
                sdi = v
                break
    valid = _sdi_valid_for_device(sdi, str(device_id), dump if isinstance(dump, dict) else {}, wire_len)
    if not valid and is_trusted_sdi_token(sdi):
        print(f"[oracle] reject stale sdi for did={device_id}")
        sdi = ""
    ok = (is_trusted_sdi_token(sdi) and valid) or wire_len > 600
    return {
        "ok": ok,
        "sdi": sdi if ok and is_trusted_sdi_token(sdi) else "",
        "wire_len": wire_len,
        "wire_hex": wire_hex[:128],
        "prime": result,
        "reason": "ok" if ok else "stale_or_no_ttnet_sdi",
    }


def _rpc_export(sc, name: str, *args, timeout: float = 90):
    fn = getattr(sc.exports_sync, name, None)
    if fn is None:
        camel = name.split("_")[0] + "".join(p.title() for p in name.split("_")[1:])
        fn = getattr(sc.exports_sync, camel, None)
    if fn is None:
        raise AttributeError(name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(fn, *args).result(timeout=timeout)


def _wait_metasec(sc, rounds: int = 60) -> bool:
    for i in range(rounds):
        try:
            ping = sc.exports_sync.ping()
            if ping.get("metasec_base"):
                print(f"[oracle] metasec ready @ {i}s base={ping.get('metasec_base')}")
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def oracle_ttnet_wire(
    device_id: str,
    install_id: str,
    profile: dict | None = None,
    app_version: str = "40.7.0",
) -> dict:
    """PC inner proto + phone MS.a/ttnet encrypt -> wire + optional SDI (Kanxue path)."""
    _restart_frida_server()
    wake_screen()
    ensure_douyin_running(wait_sec=25.0)
    if profile is None:
        profile = json.loads((ROOT / "config/device_profile.json").read_text(encoding="utf-8"))
    reg = {
        "device_id": str(device_id),
        "install_id": str(install_id),
        "openudid": str(profile.get("openudid") or ""),
        "cdid": str(profile.get("cdid") or ""),
    }
    from mssdk_proto import build_inner_device_message

    inner = build_inner_device_message(profile, reg)
    inner_hex = inner.hex()
    print(f"[oracle] ttnet inner_len={len(inner)} did={device_id}")

    dev = frida.get_usb_device(timeout=15)
    sess, pid, mode = _attach_session(dev)
    print(f"[oracle] ttnet {mode} pid={pid}")
    source = frida.Compiler().build(str(PATHB_SCRIPT), project_root=str(ROOT / "capture"))
    sc = sess.create_script(source)
    sc.on("message", lambda m, _: print("ERR", (m.get("stack") or m.get("description") or "")[:300]) if m.get("type") == "error" else None)
    sc.load()
    if mode == "spawn":
        dev.resume(pid)
        time.sleep(14)
    if not _wait_metasec(sc, rounds=75):
        try:
            sess.detach()
        except Exception:
            pass
        return {"ok": False, "reason": "no_metasec", "wire_len": 0, "sdi": ""}
    wires: dict = {}
    tr: dict = {"ok": False}
    try:
        _rpc_export(sc, "bindTargetDevice", str(device_id), str(install_id), timeout=45)
        if hasattr(sc.exports_sync, "arm_passive_hooks"):
            _rpc_export(sc, "arm_passive_hooks", False, timeout=60)
            print("[oracle] passive hooks armed (MS.b + ttnet)")
        time.sleep(2)
        tr = _rpc_export(
            sc,
            "triggerOnlyTtnet",
            str(device_id),
            str(install_id),
            str(app_version),
            inner_hex,
            timeout=120,
        )
        print(
            f"[oracle] triggerOnlyTtnet -> {json.dumps({k: tr.get(k) for k in ('ok', 'wire_len', 'wire_key', 'sdi_hex')}, ensure_ascii=False)}"
        )
        try:
            wires = _rpc_export(sc, "wires", timeout=15) or {}
            interesting = {
                k: int((v or {}).get("len") or 0)
                for k, v in wires.items()
                if int((v or {}).get("len") or 0) > 32
            }
            if interesting:
                print(f"[oracle] wires {interesting}")
        except Exception as e:
            print(f"[oracle] wires skip: {e}")
    except Exception as e:
        print(f"[oracle] triggerOnlyTtnet fail: {e}")
        tr = {"ok": False, "error": str(e)}
    finally:
        try:
            sess.detach()
        except Exception:
            pass

    wire_len = int(tr.get("wire_len") or 0)
    wire_hex = str(tr.get("wire_hex") or "")
    sdi_hex = str(tr.get("sdi_hex") or "")
    sign_headers = tr.get("sign_headers") or {}
    if wire_len < 600 and wires:
        for key in (
            "ttnet-full-outer",
            "ttnet-get_token-req",
            "msb-out:http_reqsign",
            "encrypt-reqsign",
            "http_reqsign",
        ):
            w = wires.get(key) or {}
            wl = int(w.get("len") or 0)
            wh = str(w.get("hex") or "")
            if wl >= 64 and wh and not wh.startswith("0a0821"):
                wire_len, wire_hex = wl, wh
                print(f"[oracle] pick wire key={key} len={wl}")
                break
        if wire_len < 64:
            best_key, best_len, best_hex = "", 0, ""
            for k, w in wires.items():
                wl = int((w or {}).get("len") or 0)
                wh = str((w or {}).get("hex") or "")
                if wl > best_len and wh and not wh.startswith("0a0821"):
                    best_key, best_len, best_hex = k, wl, wh
            if best_len >= 64:
                wire_len, wire_hex = best_len, best_hex
                print(f"[oracle] pick best wire key={best_key} len={best_len}")
    if wire_len >= 600 and wire_hex:
        try:
            raw = bytes.fromhex(wire_hex[: wire_len * 2])
            WIRE_BIN.write_bytes(raw)
        except Exception:
            pass
    prof_did, prof_sdi = _profile_sdi()
    if sdi_hex and prof_sdi and sdi_hex == prof_sdi and str(device_id) != prof_did:
        print(f"[oracle] ttnet reject stale sdi for did={device_id}")
        sdi_hex = ""
    ok = wire_len >= 64 or (is_trusted_sdi_token(sdi_hex) and sdi_hex != prof_sdi)
    return {
        "ok": ok,
        "sdi": sdi_hex if is_trusted_sdi_token(sdi_hex) else "",
        "wire_len": wire_len,
        "wire_hex": wire_hex[: wire_len * 2] if wire_len else wire_hex[:512],
        "sign_headers": sign_headers,
        "inner_hex": inner_hex,
        "reason": "ok" if ok else "no_ttnet_wire",
        "prime": tr,
    }


def oracle_sdi_with_retry(device_id: str, install_id: str, app_version: str = "40.7.0") -> dict:
    _restart_frida_server()
    try:
        profile = json.loads((ROOT / "config/device_profile.json").read_text(encoding="utf-8"))
    except Exception:
        profile = {}
    tt = oracle_ttnet_wire(device_id, install_id, profile=profile, app_version=app_version)
    if tt.get("ok"):
        return tt
    return oracle_sdi(device_id, install_id, app_version, use_sign_rpc=False, spawn_wait=22.0)


if __name__ == "__main__":
    did = sys.argv[1] if len(sys.argv) > 1 else ""
    iid = sys.argv[2] if len(sys.argv) > 2 else ""
    sign_only = "--sign" in sys.argv
    if not did or not iid:
        print("usage: oracle_sdi.py <device_id> <install_id> [--sign]")
        raise SystemExit(2)
    r = oracle_sdi(did, iid, use_sign_rpc=sign_only) if sign_only else oracle_sdi_with_retry(did, iid)
    print(json.dumps(r, ensure_ascii=False, indent=2))
    raise SystemExit(0 if r.get("ok") else 1)
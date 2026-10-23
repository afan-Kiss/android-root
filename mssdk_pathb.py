"""Path B: Python protobuf + native encrypt (unidbg) + MSSDK HTTP get_token."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"E:\douyin-android-sign")
WS = Path(r"e:\我的源码目录\安卓ROOT")
if str(WS) not in sys.path:
    sys.path.insert(0, str(WS))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from mssdk_proto import build_inner_device_message, build_outer_http_body
from mssdk_http import post_get_token, extract_hex_sdi_from_response

JAVA = ROOT / "tools/jdk-17/bin/java.exe"
JAR = ROOT / "project/douyin-metasec-sign/target/douyin-metasec-sign.jar"
APK = ROOT / "apk/douyin.apk"
CALIBRATE_JSON = ROOT / "config/pathb_calibrate.json"
OFFSETS_407_JSON = ROOT / "config/pathb_offsets_407.json"
PHONE_WIRE_BIN = ROOT / "config/mssdk_wire_body.bin"
DEFAULT_VM_OFFSETS = "0x17b8fc"


def _load_calibrate_json() -> dict:
    if not CALIBRATE_JSON.is_file():
        return {}
    try:
        return json.loads(CALIBRATE_JSON.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_sign_headers(cal: dict | None = None) -> dict:
    data = cal if cal is not None else _load_calibrate_json()
    ttnet = ((data.get("wire_bodies") or {}).get("ttnet-full-outer-hdrs") or {}).get("headers") or {}
    if ttnet:
        return {str(k): str(v) for k, v in ttnet.items() if k and v}
    hdrs = data.get("sign_headers") or {}
    return {str(k): str(v) for k, v in hdrs.items() if k and v}


def _load_calibrate_offsets() -> str:
    """40.7 encrypt VM offsets (comma-separated hex)."""
    env = os.environ.get("METASEC_PATHB_VM_OFFSETS", "").strip()
    if env:
        return env
    if OFFSETS_407_JSON.is_file():
        try:
            data = json.loads(OFFSETS_407_JSON.read_text(encoding="utf-8"))
            disc = data.get("discovered") or {}
            primary = disc.get("encrypt_vm_entry")
            if primary:
                extras = [
                    disc.get("proto_serialize_wrapper"),
                    disc.get("proto_string_assign_fn"),
                ]
                parts = [str(primary)] + [str(x) for x in extras if x]
                return ",".join(dict.fromkeys(parts))
        except Exception:
            pass
    if CALIBRATE_JSON.is_file():
        try:
            data = json.loads(CALIBRATE_JSON.read_text(encoding="utf-8"))
            hits = [s for s in (data.get("samples") or []) if str(s.get("kind", "")).startswith("native@")]
            offs = []
            for h in hits:
                kind = str(h.get("kind", ""))
                if kind.startswith("native@"):
                    offs.append(kind.split("@", 1)[1])
            if offs:
                return ",".join(dict.fromkeys(offs))
        except Exception:
            pass
    return DEFAULT_VM_OFFSETS


def _metasec_props(profile_path: Path, work_dir: Path) -> list[str]:
    from mssdk_trust import _metasec_props as trust_props

    replace = {
        "metasec.prime.sdi.gettoken": "false",
        "metasec.sdi.real.http": "false",
        "metasec.skip.report": "true",
        "metasec.native.report": "false",
        "metasec.vm.bytecode.host.prime.native": "false",
        "metasec.vm.bytecode.host.prime.lookup": "true",
        "metasec.mssdk.gen.count": "6",
        "metasec.sign.feature.timeout.ms": "45000",
        "metasec.dispatcher.br.fix": "true",
        "metasec.dispatcher.f64.rewrite": "true",
        "metasec.vm.run.assist": "true",
    }
    merged: dict[str, str] = {}
    for p in trust_props(profile_path, work_dir):
        if not p.startswith("-D") or "=" not in p:
            continue
        k, v = p[2:].split("=", 1)
        merged[k] = v
    merged.update(replace)
    return [f"-D{k}={v}" for k, v in merged.items()]


def _parse_encrypt_log(text: str) -> dict:
    out: dict = {}
    m = re.search(r"pathb_encrypted_len=(\d+)", text)
    if m:
        out["encrypted_len"] = int(m.group(1))
    m = re.search(r"pathb_wire_len=(\d+)", text)
    if m:
        out["wire_len"] = int(m.group(1))
    m = re.search(r"pathb_encrypted_hex=([0-9a-fA-F]+)", text)
    if m:
        out["encrypted_hex"] = m.group(1)
    m = re.search(r"pathb_wire_hex=([0-9a-fA-F]+)", text)
    if m:
        out["wire_hex"] = m.group(1)
    m = re.search(r"pathb_reason=([^\s]+)", text)
    if m:
        out["reason"] = m.group(1)
    m = re.search(r"pathb_ok=(true|false)", text)
    if m:
        out["ok"] = m.group(1) == "true"
    return out


def native_encrypt_inner(profile_path: Path, work_dir: Path, inner: bytes, timeout: int = 420) -> dict:
    if not JAR.exists() or not JAVA.exists():
        return {"ok": False, "reason": "metasec_jar_missing"}
    plain_path = work_dir / "pathb_inner.pb"
    plain_path.write_bytes(inner)
    log = work_dir / "pathb_encrypt.log"
    env = os.environ.copy()
    env["METASEC_WORK_BASE"] = str(work_dir)
    env["METASEC_DEVICE_PROFILE"] = str(profile_path)
    vm_offsets = _load_calibrate_offsets()
    props = _metasec_props(profile_path, work_dir) + [
        f"-Dmetasec.pathb.plain.file={plain_path}",
        f"-Dmetasec.pathb.vm.offset={os.environ.get('METASEC_PATHB_VM_OFFSET', DEFAULT_VM_OFFSETS)}",
        f"-Dmetasec.pathb.vm.offsets={DEFAULT_VM_OFFSETS}",
        f"-Dmetasec.pathb.eFunc.max={os.environ.get('METASEC_PATHB_EFUNC_MAX', '3')}",
        "-Dmetasec.pathb.skip.407.early=false",
        "-Dmetasec.pathb.skip.kanxue.early=true",
        "-Dmetasec.pathb.407.fast=true",
        "-Dmetasec.pathb.407.debug=true",
        "-Dmetasec.pathb.407.ms=25000",
        "-Dmetasec.pathb.407.prime.ms=15000",
        "-Dmetasec.skip.vm.bytecode.host.prime=false",
        "-Dmetasec.vm.bytecode.host.prime.lookup=true",
        "-Dmetasec.skip.pathb.bytecode.deferred.init=true",
        "-Dmetasec.vm.bytecode.host.prime.lookup=true",
        "-Dmetasec.pathb.native.chain="
        + os.environ.get("METASEC_PATHB_NATIVE_CHAIN", "false"),
        "-Dmetasec.pathb.vm.force.kanxue.root=false",
        "-Dmetasec.pathb.abi.max=2",
        "-Dmetasec.pathb.efunc.ms=3000",
        "-Dmetasec.pathb.kanxue.ms=2000",
        "-Dmetasec.pathb.deferred.vm.ms=5000",
        "-Dmetasec.pathb.deferred.vm.tail=false",
        "-Dmetasec.pathb.deferred.vm.relaxed.health=true",
        "-Dmetasec.vm.deferred.dispatch.via.loop=true",
        "-Dmetasec.vm.deferred.vmrun.scratch.stack=false",
        "-Dmetasec.skip.pathb.reqsign.direct=true",
        "-Dmetasec.skip.pathb.wire.msb="
        + os.environ.get("METASEC_SKIP_PATHB_WIRE_MSB", "true"),
        "-Dmetasec.pathb.native.only=true",
        "-Dmetasec.skip.gettoken.prime=true",
        "-Dmetasec.skip.warmup=true",
    ]
    jvm_mem = os.environ.get("METASEC_JVM_MEM", "-Xms128m -Xmx512m -XX:+UseSerialGC").split()
    cmd = [str(JAVA)] + jvm_mem + props + ["-cp", str(JAR), "com.ide.tiktok.metasec.SdiPathBEncrypt"]
    try:
        with log.open("w", encoding="utf-8") as lf:
            r = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, timeout=timeout, env=env)
        text = log.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"ok": False, "reason": "encrypt_subprocess_error", "error": str(e)}
    parsed = _parse_encrypt_log(text)
    wire_hex = parsed.get("wire_hex") or parsed.get("encrypted_hex") or ""
    wire = bytes.fromhex(wire_hex) if wire_hex else b""
    ok = bool(parsed.get("ok")) and len(wire) > 16 and wire != inner
    return {
        "ok": ok,
        "wire": wire if ok else b"",
        "wire_len": len(wire),
        "inner_len": len(inner),
        "log": str(log),
        "reason": parsed.get("reason") or ("ok" if ok else "pathb_encrypt_empty"),
        "parsed": parsed,
        "plaintext_echo": bool(wire) and wire == inner,
    }


def _json_safe(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


def _try_phone_captured_wire(reg: dict, profile: dict, inner: bytes, proxies=None) -> dict:
    """Post phone-captured encrypted wire (profile device only)."""
    if os.environ.get("MSSDK_PATHB_PHONE_WIRE", "").strip() not in ("1", "true", "yes"):
        return {"ok": False, "reason": "phone_wire_disabled"}
    prof_did = str(profile.get("deviceId") or "")
    if prof_did and str(reg.get("device_id")) != prof_did:
        return {"ok": False, "reason": "phone_wire_device_mismatch"}
    if not PHONE_WIRE_BIN.is_file() or PHONE_WIRE_BIN.stat().st_size < 32:
        return {"ok": False, "reason": "no_phone_wire_bin"}
    wire = PHONE_WIRE_BIN.read_bytes()
    if wire == inner or (len(wire) == len(inner) and wire[:32] == inner[:32]):
        return {"ok": False, "reason": "phone_wire_plaintext_echo"}
    resp = post_get_token(reg, profile, wire, proxies=proxies)
    token = extract_hex_sdi_from_response(resp.get("body") or b"")
    ok = bool(token) and len(token) >= 64 and not token.startswith("{")
    return {
        "ok": ok,
        "sdi": token,
        "sdi_len": len(token) if token else 0,
        "http_status": resp.get("status"),
        "wire_len": len(wire),
        "wire_source": "phone_captured",
        "reason": "ok" if ok else "get_token_no_hex_sdi",
    }


def path_b_get_token(profile: dict, reg: dict, profile_path: Path, work_dir: Path,
                     proxies=None, timeout: int = 420) -> dict:
    work_dir.mkdir(parents=True, exist_ok=True)
    inner = build_inner_device_message(profile, reg)
    inner_path = work_dir / "pathb_inner.pb"
    inner_path.write_bytes(inner)
    enc = native_encrypt_inner(profile_path, work_dir, inner, timeout=timeout)
    wire = enc.get("wire") or b""
    wire_source = "unidbg"
    if not wire:
        phone = _try_phone_captured_wire(reg, profile, inner, proxies=proxies)
        if phone.get("ok"):
            return {
                **phone,
                "inner_len": len(inner),
                "encrypt": enc,
            }
        return {
            "ok": False,
            "reason": enc.get("reason") or phone.get("reason") or "no_wire_body",
            "inner_len": len(inner),
            "encrypt": enc,
            "phone_wire": phone,
            "hint": "run: python E:\\douyin-android-sign\\scripts\\pathb_phone_calibrate.py",
        }
    if not wire.startswith(b"\x0a") and not wire.startswith(b"\x12"):
        wire = build_outer_http_body(inner, wire)
    wire_path = work_dir / "pathb_wire.bin"
    wire_path.write_bytes(wire)
    sign_hdrs = _load_sign_headers()
    resp = post_get_token(reg, profile, wire, proxies=proxies, sign_headers=sign_hdrs or None)
    token = extract_hex_sdi_from_response(resp.get("body") or b"")
    ok = bool(token) and len(token) >= 64 and not token.startswith("{")
    return {
        "ok": ok,
        "sdi": token,
        "sdi_len": len(token) if token else 0,
        "http_status": resp.get("status"),
        "wire_len": len(wire),
        "wire_source": wire_source,
        "inner_len": len(inner),
        "encrypt": enc,
        "signed": bool(sign_hdrs),
        "reason": "ok" if ok else "get_token_no_hex_sdi",
    }


if __name__ == "__main__":
    import argparse
    from profile_tools import load_json

    ap = argparse.ArgumentParser(description="MSSDK Path B get_token test")
    ap.add_argument("--profile", default=str(ROOT / "config/device_profile.json"))
    ap.add_argument("--work", default="")
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--install-id", required=True)
    ap.add_argument("--openudid", default="")
    args = ap.parse_args()
    profile = load_json(args.profile)
    reg = {
        "device_id": args.device_id,
        "install_id": args.install_id,
        "openudid": args.openudid or profile.get("openudid", ""),
    }
    work = Path(args.work) if args.work else ROOT / "tmp" / f"reg_{args.device_id}"
    prof = work / "device_profile.json"
    if not prof.is_file():
        from mssdk_trust import write_reg_profile
        prof = write_reg_profile(profile, reg, work)
    res = path_b_get_token(profile, reg, prof, work)
    print(json.dumps(_json_safe(res), ensure_ascii=False, indent=2))
    raise SystemExit(0 if res.get("ok") else 2)
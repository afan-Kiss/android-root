"""MSSDK trust: per-device profile + MetaSec native get_token prime."""
from __future__ import annotations
import json, os, re, shutil, subprocess, time
from pathlib import Path
import sys

ROOT = Path(r"E:\douyin-android-sign")
WS = Path(r"e:\我的源码目录\安卓ROOT")
_SCRIPTS = ROOT / "scripts"
for p in (WS, _SCRIPTS):
    if str(p) not in sys.path:
        sys.path.append(str(p))
JAVA = ROOT / "tools/jdk-17/bin/java.exe"
JAR = ROOT / "project/douyin-metasec-sign/target/douyin-metasec-sign.jar"
APK = ROOT / "apk/douyin.apk"
SIGN_KEY = "1128-1128-sdi"


def is_trusted_sdi_token(token: str) -> bool:
    token = (token or "").strip()
    if not token or token.startswith("{") or len(token) < 64 or len(token) > 128:
        return False
    if not re.fullmatch(r"[0-9a-fA-F]+", token):
        return False
    head = token[:4].lower()
    if head in ("7b22", "0a08", "08c4", "0890"):
        return False
    if re.match(r"^(08|0a|10|12|18|1a|22)", head) and len(token) >= 80:
        return False
    return True


def _latest_capture_msdata() -> Path | None:
    out = ROOT / "capture" / "output"
    if not out.is_dir():
        return None
    dirs = sorted(out.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    for d in dirs:
        ms = d / "msdata"
        if ms.is_dir() and any(ms.rglob(".mss_*")):
            return ms
    return None


def _prepare_work_dir(base_profile: dict, reg: dict) -> Path:
    work = ROOT / "tmp" / f"reg_{reg['device_id']}"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    ms_src = _latest_capture_msdata() or Path(base_profile.get("msdataPath") or ROOT / "config/msdata")
    ms_dst = work / "msdata"
    if ms_src.is_dir():
        shutil.copytree(ms_src, ms_dst)
    return work


def write_reg_profile(base_profile: dict, reg: dict, work_dir: Path | None = None) -> Path:
    work_dir = work_dir or (ROOT / "tmp" / f"reg_{reg['device_id']}")
    work_dir.mkdir(parents=True, exist_ok=True)
    p = json.loads(json.dumps(base_profile))
    did, iid = str(reg["device_id"]), str(reg["install_id"])
    ou = str(reg.get("openudid", ""))
    p.update(deviceId=did, installId=iid, openudid=ou, androidId=ou, cdid=str(reg.get("cdid", "")))
    arc = p.get("appRegisterConfig")
    if isinstance(arc, list) and len(arc) > 8:
        arc[6] = did
        arc[8] = iid
    prefs = dict(p.get("mssdkPrefs") or {})
    for k in list(prefs):
        if "sdi" in k.lower() or k in ("sdi_token",):
            prefs.pop(k, None)
    p["mssdkPrefs"] = prefs
    out = work_dir / "device_profile.json"
    out.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def _metasec_props(profile_path: Path, work_dir: Path) -> list[str]:
    return [
        f"-Dmetasec.work.base={work_dir}",
        f"-Dmetasec.apk={APK}",
        f"-Dmetasec.device.profile={profile_path}",
        "-Dmetasec.skip.sdi.token.load=true",
        "-Dmetasec.prime.sdi.gettoken=true",
        "-Dmetasec.stub.sdi.network=false",
        "-Dmetasec.sdi.real.http=true",
        "-Dmetasec.skip.warmup=true",
        "-Dmetasec.native.report=true",
        "-Dmetasec.skip.report=false",
        "-Dmetasec.native.marker=true",
        "-Dmetasec.bootstrap.blog.order=true",
        "-Dmetasec.coerce.http.sign.init=false",
        "-Dmetasec.coerce.http.sign.reqsign=false",
        "-Dmetasec.coerce.http.sign.url=false",
        "-Dmetasec.sdi.coerce.url=true",
        "-Dmetasec.disable.dispatcher.bridge=false",
        "-Dmetasec.http.sign.jit.patch=true",
        "-Dmetasec.sign.dispatcher.init=true",
        "-Dmetasec.sign.data.patch=true",
        "-Dmetasec.fs.materialize.fallback=true",
        "-Dmetasec.fs.fallback.msp=true",
        "-Dmetasec.jit.cas.gate.enable=true",
        "-Dmetasec.jit.cas.hword.blog=true",
        "-Dmetasec.jit.cas.converge=true",
        "-Dmetasec.dispatcher.br.fix=true",
        "-Dmetasec.skip.cronet.sign=true",
        "-Dmetasec.sign.feature.timeout.ms=60000",
        "-Dmetasec.mssdk.gen.count=6",
        "-Dmetasec.msdata.persist.session=true",
        "-Dmetasec.bootstrap.post.body=false",
        "-Dmetasec.http.sign.gen.bridge.handle=true",
        "-Dmetasec.force.app.get=true",
        "-Dmetasec.skip.native.kb=false",
        "-Dmetasec.mssdk.gen.session.only=true",
        "-Dmetasec.mssdk.gen.kb.first=true",
        "-Dmetasec.vm.bytecode.host.prime.native=true",
        "-Dmetasec.vm.bytecode.host.prime.lookup=true",
    ]


def _parse_sdi_from_log(text: str) -> dict:
    out = {}
    m = re.search(r"sdi_prefs=(\{.*?\})", text)
    if m:
        try:
            out = json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    m2 = re.search(r"native stored sdi_token len=(\d+)", text)
    if m2:
        out["_native_len"] = int(m2.group(1))
    m3 = re.search(r"sdi_token_len=(\d+)", text)
    if m3:
        out["_token_len"] = int(m3.group(1))
    if "json=true" in text:
        out["_json_placeholder"] = True
    body_m = re.search(r"prime sdi get_token body len=(\d+)", text)
    if body_m:
        out["_body_len"] = int(body_m.group(1))
    wire_m = re.search(r"wire_req_len=(\d+)", text)
    if wire_m:
        out["_wire_req_len"] = int(wire_m.group(1))
    return out


def metasec_prime(profile_path: Path, work_dir: Path, timeout: int = 120) -> dict:
    if not JAR.exists() or not JAVA.exists():
        return {"ok": False, "error": "metasec jar/java missing"}
    log = work_dir / "metasec_prime.log"
    env = os.environ.copy()
    env["METASEC_WORK_BASE"] = str(work_dir)
    env["METASEC_APK"] = str(APK)
    env["METASEC_DEVICE_PROFILE"] = str(profile_path)
    props = _metasec_props(profile_path, work_dir)
    cmd = [str(JAVA)] + props + ["-cp", str(JAR), "com.ide.tiktok.metasec.SdiTokenBootstrap"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        text = (r.stdout or "") + (r.stderr or "")
        log.write_text(text, encoding="utf-8")
    except Exception as e:
        return {"ok": False, "error": str(e)}
    sdi = _parse_sdi_from_log(text)
    token = sdi.get(SIGN_KEY) or sdi.get("sdi_token")
    wire_len = int(sdi.get("_wire_req_len") or 0)
    body_len = int(sdi.get("_body_len") or 0)
    prime_ok = body_len > 0 or wire_len > 0
    real_sdi = is_trusted_sdi_token(str(token) if token else "")
    json_placeholder = bool(sdi.get("_json_placeholder"))
    argus_m = re.search(r"x-argus_len=(\d+)|sdi_token_len=(\d+)", text)
    reason = "ok"
    if not prime_ok:
        reason = "mssdk_get_token_body_empty"
    elif json_placeholder or not real_sdi:
        reason = "sdi_json_placeholder_not_hex_blob"
    return {
        "ok": prime_ok and real_sdi,
        "argus_len": int(argus_m.group(1) or argus_m.group(2) or 0) if argus_m else 0,
        "sdi_len": len(str(token)) if token else 0,
        "wire_req_len": wire_len,
        "body_len": body_len,
        "sdi": sdi,
        "log": str(log),
        "prime": prime_ok,
        "real_sdi": real_sdi,
        "reason": reason,
    }


CAPTURED_SDI_HEX = (ROOT / "config/captured_sdi_token.txt").read_text(encoding="utf-8").strip() if (ROOT / "config/captured_sdi_token.txt").exists() else ""


def apply_sdi_hex(profile_path: Path, token: str) -> bool:
    token = (token or "").strip()
    if not token or token.startswith("{") or len(token) < 32:
        return False
    p = json.loads(profile_path.read_text(encoding="utf-8"))
    prefs = dict(p.get("mssdkPrefs") or {})
    for k in ("1128-1128-sdi", "1128-0-sdi", "1128-0-0-sdi", "sdi_token"):
        prefs[k] = token
    p["mssdkPrefs"] = prefs
    profile_path.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding="utf-8")
    return True


def apply_sdi_to_profile(profile_path: Path, sdi: dict) -> None:
    token = sdi.get("1128-1128-sdi") or sdi.get("sdi_token")
    if token and not str(token).startswith("{"):
        apply_sdi_hex(profile_path, str(token))


def _load_calibrate_sign_headers(cal_path: Path | None = None) -> dict:
    paths = [cal_path, ROOT / "config/pathb_calibrate.json"]
    for p in paths:
        if not p or not Path(p).is_file():
            continue
        try:
            data = json.loads(Path(p).read_text(encoding="utf-8"))
            ttnet = ((data.get("wire_bodies") or {}).get("ttnet-full-outer-hdrs") or {}).get("headers") or {}
            if ttnet:
                return {str(k): str(v) for k, v in ttnet.items() if k and v}
            hdrs = data.get("sign_headers") or {}
            return {str(k): str(v) for k, v in hdrs.items() if k and v}
        except Exception:
            continue
    return {}


def _apply_wire_http(
    reg: dict,
    profile: dict,
    prof_path: Path,
    body: bytes,
    proxies=None,
    sign_headers: dict | None = None,
) -> bool:
    if not body or len(body) < 32:
        return False
    from mssdk_http import post_get_token, extract_hex_sdi_from_response

    hdrs = sign_headers or _load_calibrate_sign_headers()
    resp = post_get_token(reg, profile, body, proxies=proxies, sign_headers=hdrs or None)
    tok = extract_hex_sdi_from_response(resp.get("body") or b"")
    if tok and apply_sdi_hex(prof_path, tok):
        print(f"[trust] wire+http sdi len={len(tok)} status={resp.get('status')} signed={bool(hdrs)}")
        return True
    return False


def _try_phone_calibrate(reg: dict, profile: dict, prof_path: Path, work: Path) -> dict:
    if os.environ.get("MSSDK_PHONE_CALIBRATE", "1").strip() not in ("1", "true", "yes"):
        return {"ok": False, "reason": "disabled"}
    script = ROOT / "scripts/pathb_phone_calibrate.py"
    if not script.is_file():
        script = WS / "pathb_phone_calibrate.py"
    did, iid = str(reg["device_id"]), str(reg["install_id"])
    cal_out = work / "pathb_calibrate.json"
    flags = ["--passive-only", "--short-passive"]
    cmd = [sys.executable, str(script), did, iid] + flags
    print(f"[trust] phone calibrate did={did} flags={flags}")
    try:
        r = subprocess.run(cmd, cwd=str(ROOT), timeout=600, capture_output=False)
        src = ROOT / "config/pathb_calibrate.json"
        if src.is_file():
            cal_out.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        if not cal_out.is_file():
            return {"ok": False, "reason": "no_calibrate_output", "exit": r.returncode}
        data = json.loads(cal_out.read_text(encoding="utf-8"))
        wire_hex = str(data.get("wire_sdi_hex") or data.get("wire_hex") or "")
        wire_len = int(data.get("wire_len") or 0)
        if data.get("ok") and wire_hex and wire_len > 32:
            body = bytes.fromhex(wire_hex[: wire_len * 2])
            hdrs = _load_calibrate_sign_headers(cal_out)
            if _apply_wire_http(reg, profile, prof_path, body, sign_headers=hdrs):
                return {"ok": True, "reason": "verified_wire", "wire_len": wire_len, "calibrate": data}
        tok = str(data.get("wire_sdi_hex") or data.get("sdi_hex") or "")
        if is_trusted_sdi_token(tok) and apply_sdi_hex(prof_path, tok):
            return {"ok": True, "reason": "calibrate_sdi_hex", "sdi_len": len(tok), "calibrate": data}
        return {"ok": False, "reason": data.get("wire_rejected") or "calibrate_no_sdi", "calibrate": data, "exit": r.returncode}
    except Exception as e:
        return {"ok": False, "reason": "calibrate_exception", "error": str(e)}


def trust_pipeline(profile: dict, reg: dict, proxies=None, phone_sdi: bool = False, phone_oracle: bool = True) -> dict:
    from device_warmup import full_warmup
    work = _prepare_work_dir(profile, reg)
    warm = full_warmup(profile, reg, proxies=proxies, app_log_rounds=3)
    prof_path = write_reg_profile(profile, reg, work)
    sdi_applied = False
    sdi_source = "none"
    prime = {"ok": False, "real_sdi": False, "reason": "skipped"}

    def _apply_oracle_result(o: dict) -> bool:
        tok = str(o.get("sdi") or "")
        reg_did = str(reg.get("device_id") or "")
        prof_did = str(profile.get("deviceId") or "")
        if (
            tok
            and prof_did
            and reg_did != prof_did
            and tok == CAPTURED_SDI_HEX
            and int(o.get("wire_len") or 0) <= 0
        ):
            print(f"[trust] reject stale oracle SDI for new did={reg_did}")
            tok = ""
        if tok and apply_sdi_hex(prof_path, tok):
            return True
        wire_len = int(o.get("wire_len") or 0)
        wire_hex = str(o.get("wire_hex") or "")
        sign_headers = o.get("sign_headers") or {}
        body = b""
        if wire_len >= 32 and wire_hex:
            try:
                body = bytes.fromhex(wire_hex[: wire_len * 2])
            except Exception:
                body = b""
        if not body:
            wire_bin = ROOT / "config/mssdk_wire_body.bin"
            if wire_bin.is_file():
                body = wire_bin.read_bytes()
        if body and len(body) >= 32:
            return _apply_wire_http(
                reg, profile, prof_path, body, proxies=proxies, sign_headers=sign_headers or None
            )
        return False

    if phone_oracle:
        try:
            import time as _time
            from phone_mssdk_oracle import oracle_sdi_with_retry
            ver = str(profile.get("appVersion") or "40.7.0")
            print(f"[trust] phone oracle first did={reg['device_id']}")
            _time.sleep(2)
            o = oracle_sdi_with_retry(str(reg["device_id"]), str(reg["install_id"]), ver)
            if _apply_oracle_result(o):
                sdi_applied = True
                sdi_source = "phone_oracle"
            elif not o.get("ok"):
                print("[trust] phone oracle miss:", {k: o.get(k) for k in ("ok", "wire_len", "sdi")})
        except Exception as e:
            print("[trust] phone oracle error:", e)

    calibrate = {"ok": False, "reason": "skipped"}
    if not sdi_applied and os.environ.get("MSSDK_PHONE_CALIBRATE", "1").strip() in ("1", "true", "yes"):
        try:
            calibrate = _try_phone_calibrate(reg, profile, prof_path, work)
            if calibrate.get("ok"):
                sdi_applied = True
                sdi_source = "phone_calibrate"
            else:
                print("[trust] phone calibrate miss:", {k: calibrate.get(k) for k in ("ok", "reason")})
        except Exception as e:
            calibrate = {"ok": False, "reason": "calibrate_error", "error": str(e)}
            print("[trust] phone calibrate error:", e)

    pathb = {"ok": False, "reason": "skipped"}
    use_pathb = os.environ.get("MSSDK_PATH_B", "1").strip() not in ("0", "false", "no")
    if not sdi_applied and use_pathb:
        try:
            from mssdk_pathb import path_b_get_token
            print(f"[trust] path B get_token did={reg['device_id']}")
            pathb = path_b_get_token(profile, reg, prof_path, work, proxies=proxies, timeout=420)
            tok = str(pathb.get("sdi") or "")
            if tok and apply_sdi_hex(prof_path, tok):
                sdi_applied = True
                sdi_source = "path_b"
                print(f"[trust] path B sdi len={len(tok)} wire={pathb.get('wire_len')}")
            elif not pathb.get("ok"):
                print("[trust] path B miss:", {k: pathb.get(k) for k in ("ok", "reason", "wire_len", "inner_len")})
        except Exception as e:
            pathb = {"ok": False, "reason": "pathb_exception", "error": str(e)}
            print("[trust] path B error:", e)

    skip_metasec = os.environ.get("SKIP_METASEC_PRIME", "").strip() in ("1", "true", "yes")
    if not sdi_applied and not skip_metasec:
        prime = metasec_prime(prof_path, work, timeout=75)
    elif skip_metasec and not sdi_applied:
        print("[trust] SKIP_METASEC_PRIME=1, skip unidbg")
    if prime.get("real_sdi"):
        apply_sdi_to_profile(prof_path, prime.get("sdi") or {})
        sdi_applied = True
        sdi_source = "native"
    elif os.environ.get("METASEC_SDI_FALLBACK") == "1" and CAPTURED_SDI_HEX:
        sdi_applied = apply_sdi_hex(prof_path, CAPTURED_SDI_HEX)
        if sdi_applied:
            sdi_source = "captured_hex"
    elif os.environ.get("PHONE_SDI_TRUST") == "1" and CAPTURED_SDI_HEX and is_trusted_sdi_token(CAPTURED_SDI_HEX):
        sdi_applied = apply_sdi_hex(prof_path, CAPTURED_SDI_HEX)
        if sdi_applied:
            sdi_source = "captured_hex"
    elif (
        not prime.get("real_sdi")
        and CAPTURED_SDI_HEX
        and is_trusted_sdi_token(CAPTURED_SDI_HEX)
        and str(reg.get("device_id")) == str(profile.get("deviceId") or "")
    ):
        sdi_applied = apply_sdi_hex(prof_path, CAPTURED_SDI_HEX)
        if sdi_applied:
            sdi_source = "captured_hex"
    elif not sdi_applied and str(reg.get("device_id")) == str(profile.get("deviceId") or ""):
        prefs = profile.get("mssdkPrefs") or {}
        for key in ("1128-1128-sdi", "1128-0-sdi", "sdi_token"):
            tok = str(prefs.get(key) or "")
            if is_trusted_sdi_token(tok) and apply_sdi_hex(prof_path, tok):
                sdi_applied = True
                sdi_source = "profile_hex"
                break
    if not sdi_applied and phone_sdi:
        try:
            import phone_sdi_capture
            ver = str(profile.get("appVersion") or "40.7.0")
            token = phone_sdi_capture.capture_sdi_on_phone(
                str(reg["device_id"]),
                str(reg["install_id"]),
                ver,
                profile_out=prof_path,
            )
            if token and apply_sdi_hex(prof_path, token):
                sdi_applied = True
                sdi_source = "phone_frida"
        except Exception as e:
            print("[trust] phone_sdi capture error:", e)
    if not sdi_applied and phone_sdi:
        try:
            from mssdk_http import try_wire_file_post
            wire = try_wire_file_post(reg, profile, proxies=proxies)
            tok = str(wire.get("sdi_hex") or "")
            if tok and apply_sdi_hex(prof_path, tok):
                sdi_applied = True
                sdi_source = "phone_wire_http"
                print(f"[trust] wire http sdi len={len(tok)} status={wire.get('status')}")
        except Exception as e:
            print("[trust] wire http error:", e)
    trust_ok = bool(sdi_applied)
    blocker = ""
    if not trust_ok:
        blocker = calibrate.get("reason") or pathb.get("reason") or prime.get("reason") or "sdi_not_applied"
    return {
        "warmup": warm,
        "profile": str(prof_path),
        "metasec": prime,
        "calibrate": calibrate,
        "pathb": pathb,
        "work_dir": str(work),
        "sdi_applied": sdi_applied,
        "sdi_source": sdi_source,
        "trust_ok": trust_ok,
        "blocker": blocker,
    }

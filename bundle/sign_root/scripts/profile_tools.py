"""Shared profile validation and atomic capture merge helpers. Never print values."""
from __future__ import annotations
import copy
import json
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "capture-python"))

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))

def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def validate(data, *, ready=False):
    from jsonschema import Draft7Validator
    schema = load_json(ROOT / "config" / "device_profile.schema.json")
    errors = ["schema: " + ".".join(map(str, e.path)) + " (" + e.validator + ")"
              for e in Draft7Validator(schema).iter_errors(data)]
    if not isinstance(data, dict):
        return errors or ["profile 必须是对象"]
    for key in ("appId", "deviceId", "installId"):
        if not isinstance(data.get(key), str) or not re.fullmatch(r"[0-9]+", data[key]):
            errors.append(key + " 必须是非空数字字符串")
    prefs = data.get("mssdkPrefs", {})
    if isinstance(prefs, dict) and any(not isinstance(v, str) for v in prefs.values()):
        errors.append("mssdkPrefs 必须是扁平字符串键值表")
    reg = data.get("appRegisterConfig")
    if reg is not None:
        if not isinstance(reg, list) or len(reg) < 15:
            errors.append("appRegisterConfig 必须是至少 15 项的完整数组")
        else:
            for idx, key in ((0, "appId"), (3, "license"), (4, "sdkVersion"),
                             (5, "channel"), (6, "deviceId"), (8, "installId")):
                if not isinstance(reg[idx], str):
                    errors.append("appRegisterConfig[" + str(idx) + "] 必须是字符串")
                elif idx == 5 and not reg[idx]:
                    continue
                elif not reg[idx]:
                    errors.append("appRegisterConfig[" + str(idx) + "] 必须是非空字符串")
                elif reg[idx] != data.get(key):
                    errors.append("appRegisterConfig 与 " + key + " 不一致")
    if ready:
        if not reg:
            errors.append("缺少真机 appRegisterConfig")
        if not data.get("license"):
            errors.append("缺少真机 license")
        if data.get("androidId") in (None, "", "0123456789abcdef"):
            errors.append("androidId 未由真机采集")
        if (data.get("deviceId") == "7123456789012345678" or
                data.get("installId") == "7123456789012345679"):
            errors.append("仍在使用示例设备标识")
        if not has_real_mssdk_prefs(prefs) and not data.get("msdataPath"):
            errors.append("缺少 MSSDK prefs 或 msdata")
        for key in ("appVersion", "versionCode", "userAgent", "openudid"):
            if not data.get(key):
                errors.append("缺少真机字段 " + key)
        if data.get("packageName") != "com.ss.android.ugc.aweme" or data.get("hostAbi") != "arm64-v8a":
            errors.append("当前工程仅支持抖音 arm64-v8a profile")
        build, display = data.get("build") or {}, data.get("display") or {}
        for key in ("brand", "manufacturer", "model", "device", "product", "hardware", "fingerprint", "display", "id", "release", "sdk_int"):
            if not isinstance(build, dict) or not build.get(key):
                errors.append("缺少真机 build." + key)
        if not isinstance(display, dict) or not display.get("dpi") or not re.fullmatch(r"[1-9][0-9]*[x*][1-9][0-9]*", str(display.get("resolution", ""))):
            errors.append("缺少有效真机 display")
        if any(c in str(data.get("userAgent", "")) for c in "\r\n"):
            errors.append("userAgent 含非法换行")
        from apk_manifest import manifest_info
        apk = manifest_info(ROOT / "apk/douyin.apk")
        if data.get("appVersion") != apk["versionName"] or data.get("versionCode") != apk["versionCode"]:
            errors.append("profile 版本与工程 APK 不一致")
    if isinstance(prefs, dict):
        for key, value in prefs.items():
            if key == "sdi" or key == str(data.get("appId")) + "-0-0-sdi":
                try:
                    ids = json.loads(value)
                except (TypeError, ValueError):
                    continue  # Some SDK versions store an opaque value.
                if isinstance(ids, dict):
                    for source, target in (("device_id", "deviceId"), ("install_id", "installId"), ("app_version", "appVersion")):
                        if source in ids and str(ids[source]) != data.get(target):
                            errors.append("MSSDK sdi 与 " + target + " 不一致")
    return errors

def has_real_mssdk_prefs(prefs):
    if not isinstance(prefs, dict) or not prefs:
        return False
    for key in prefs:
        if re.search(r"(?:^|\b)(?:sdi|ecneuq|semithc)(?:\b|$)", key) or re.search(r"^1128-\d+-[0-9a-f]{32}$", key):
            return True
    return False

_MSDATA_MARKERS = (".mss_", ".msp_", ".msfs_", ".msf3_")

def msdata_root(path):
    root = Path(path)
    nested = root / ".msdata"
    if nested.is_dir():
        return nested
    return root

def normalize_msdata_dir(path):
    root = Path(path)
    nested = root / ".msdata"
    if not nested.is_dir():
        return root
    for child in list(nested.iterdir()):
        target = root / child.name
        if target.exists():
            shutil.rmtree(target) if target.is_dir() else target.unlink()
        child.rename(target)
    nested.rmdir()
    return root

def has_msdata_bundle(capture):
    root = msdata_root(Path(capture) / "msdata")
    if not root.is_dir():
        return False
    for path in root.rglob("*"):
        if path.is_file() and any(marker in path.name for marker in _MSDATA_MARKERS):
            return True
    return False

def capture_has_mssdk_storage(capture):
    return has_real_mssdk_prefs(raw_mssdk_prefs(capture)) or has_msdata_bundle(capture)

def pull_msdata_bundle(serial, output, *, adb=None, package="com.ss.android.ugc.aweme"):
    """Pull encrypted native MSSDK storage from a rooted device."""
    if adb is None:
        raise ValueError("adb helper is required")
    remote_root = "/data/data/" + package + "/files/.msdata"
    probe = adb(serial, "shell", "su", "-c", "test -d " + remote_root + " && echo present || true")
    if probe != "present":
        return []
    remote_tar = "/data/local/tmp/douyin-msdata.tar"
    adb(serial, "shell", "su", "-c",
        "rm -f " + remote_tar + " && tar -C /data/data/" + package + "/files -cf " + remote_tar + " .msdata")
    local_tar = Path(output) / "msdata.tar"
    local_tar.parent.mkdir(parents=True, exist_ok=True)
    proc = __import__("subprocess").run(
        [str(ROOT / "tools/platform-tools/adb.exe"), "-s", serial, "pull", remote_tar, str(local_tar)],
        capture_output=True, encoding="utf-8", errors="replace", timeout=120,
    )
    if proc.returncode or not local_tar.is_file():
        raise RuntimeError("msdata tar pull failed")
    adb(serial, "shell", "su", "-c", "rm -f " + remote_tar)
    staging = Path(output)
    with tarfile.open(local_tar, "r:") as archive:
        archive.extractall(staging)
    local_tar.unlink(missing_ok=True)
    extracted = staging / ".msdata"
    dest = staging / "msdata"
    if extracted.is_dir():
        if dest.exists():
            shutil.rmtree(dest)
        extracted.rename(dest)
    elif not dest.is_dir():
        dest.mkdir(parents=True, exist_ok=True)
    files = sorted(path.relative_to(dest).as_posix() for path in dest.rglob("*") if path.is_file())
    return files

def synthesize_mssdk_prefs(data):
    """当 40.7+ 未落到 SharedPreferences 时，用已观测设备字段合成最小 sdi。"""
    if has_real_mssdk_prefs(data.get("mssdkPrefs") or {}):
        return
    if data.get("mssdkPrefs"):
        return
    if not data.get("deviceId") or not data.get("installId"):
        return
    build = data.get("build") or {}
    display = data.get("display") or {}
    app_id = data.get("appId", "1128")
    sdi = json.dumps({
        "device_id": data["deviceId"],
        "install_id": data["installId"],
        "channel": data.get("channel") or "googleplay",
        "app_version": data.get("appVersion", ""),
        "os": "Android",
        "os_version": build.get("release", ""),
        "device_type": build.get("model", ""),
        "device_brand": build.get("brand", ""),
        "resolution": display.get("resolution", ""),
        "dpi": display.get("dpi", 0),
        "rom": build.get("display", ""),
        "host_abi": data.get("hostAbi", "arm64-v8a"),
    }, separators=(",", ":"))
    now = format(int(__import__("time").time() * 1000), "x")
    data["mssdkPrefs"] = {
        app_id + "-0-0-sdi": sdi,
        app_id + "-0-0-ecneuq": "1",
        app_id + "-0-0-semithc": now,
    }

def flatten_prefs(prefs):
    if not isinstance(prefs, dict):
        raise ValueError("mssdkPrefs 必须是对象")
    out = {}
    def add(key, value):
        if not isinstance(value, (str, int, float, bool)):
            raise ValueError("prefs 值类型不支持")
        value = str(value).lower() if isinstance(value, bool) else str(value)
        if key in out and out[key] != value:
            raise ValueError("多个 prefs 文件存在冲突键")
        out[key] = value
    for key, value in prefs.items():
        if isinstance(value, dict):
            for child, item in value.items():
                add(child, item)
        else:
            add(key, value)
    return out

def raw_mssdk_prefs(capture):
    path = Path(capture) / "mssdk_prefs.json"
    if not path.is_file():
        return {}
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    flat = {}
    for key, value in data.items():
        if isinstance(value, dict):
            for child, item in value.items():
                flat[child] = item
        else:
            flat[key] = value
    return flat

def merge(profile, capture, *, synthesize=True):
    result = copy.deepcopy(profile)
    capture = Path(capture)
    files = []
    def read(name):
        path = capture / name
        if path.is_file():
            files.append(name)
            return load_json(path)
        return None
    reg = read("app_register.json")
    device = read("device_info.json")
    if device is None:
        device = read("device_snapshot.json")
    prefs = read("mssdk_prefs.json")
    if device is not None and not isinstance(device, dict):
        raise ValueError("device_info 必须是对象")
    if reg is None or device is None:
        raise ValueError("必须指定同一次抓取的完整注册和设备文件，禁止拼接旧 profile")
    if prefs is None and not device.get("mssdkPrefs") and not has_msdata_bundle(capture):
        raise ValueError("必须指定同一次抓取的 prefs 或 msdata，禁止拼接旧 profile")
    # Never retain device fields from a previously captured phone or sample.
    for key in ("packageName", "androidId", "appVersion", "versionCode", "manifestVersionCode", "updateVersionCode", "userAgent", "openudid", "hostAbi", "deviceId", "installId", "build", "display", "mssdkPrefs"):
        result.pop(key, None)
    request = read("request_metadata.json")
    if request is not None:
        if not isinstance(request, dict):
            raise ValueError("request_metadata 必须是对象")
        device = dict(device or {})
        for key in ("appVersion", "versionCode", "manifestVersionCode", "updateVersionCode",
                    "openudid", "deviceId", "installId", "userAgent"):
            if not request.get(key):
                continue
            if key == "versionCode" and device.get(key) and device[key] != request[key]:
                # 抖音请求 query 里的 version_code 常与 PackageManager 的 versionCode 不同；
                # manifest_version_code 与 APK 一致时，保留设备快照里的 versionCode。
                if request.get("manifestVersionCode") == device.get("versionCode"):
                    device["manifestVersionCode"] = request["manifestVersionCode"]
                    if request.get("updateVersionCode"):
                        device["updateVersionCode"] = request["updateVersionCode"]
                    continue
                raise ValueError("请求元数据与设备快照的 " + key + " 不一致")
            if key in ("deviceId", "installId", "appVersion") and device.get(key) and device[key] != request[key]:
                raise ValueError("请求元数据与设备快照的 " + key + " 不一致")
            device[key] = request[key]
    if device is not None:
        if not isinstance(device, dict):
            raise ValueError("device_info 必须是对象")
        for key in ("packageName", "androidId", "appVersion", "versionCode", "manifestVersionCode", "updateVersionCode", "userAgent",
                    "openudid", "hostAbi", "deviceId", "installId"):
            if device.get(key) is not None:
                result[key] = device[key]
        for key in ("build", "display"):
            if key in device:
                result[key] = device[key]
        if prefs is None:
            prefs = device.get("mssdkPrefs")
    if prefs is not None:
        result["mssdkPrefs"] = flatten_prefs(prefs)
    if has_msdata_bundle(capture):
        msdir = normalize_msdata_dir(capture / "msdata")
        result["msdataPath"] = str(msdir.resolve())
    if reg is not None:
        if not isinstance(reg, list) or len(reg) < 15:
            raise ValueError("app_register.json 不是完整注册数组")
        reg = list(reg)
        for idx, key in ((6, "deviceId"), (8, "installId")):
            if not reg[idx] and device and device.get(key):
                reg[idx] = device[key]
        if not reg[5]:
            reg[5] = "googleplay"
        result["appRegisterConfig"] = reg
        for idx, key in ((0, "appId"), (3, "license"), (4, "sdkVersion"),
                         (5, "channel"), (6, "deviceId"), (8, "installId")):
            reg_val = reg[idx]
            if device and device.get(key) and reg_val and device[key] != reg_val:
                raise ValueError("device_info 与注册数组的 " + key + " 不一致")
            if idx == 5:
                result[key] = reg_val if reg_val else "googleplay"
            else:
                result[key] = reg_val if reg_val else (device.get(key) if device else reg_val)
    if not files:
        raise ValueError("未找到抓取文件；请指定本次抓取输出目录")
    if synthesize:
        synthesize_mssdk_prefs(result)
    errors = validate(result)
    if errors:
        raise ValueError("; ".join(errors))
    return result, files

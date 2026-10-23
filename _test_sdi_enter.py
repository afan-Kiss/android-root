import json, sys
from pathlib import Path
ROOT = Path(r"E:\douyin-android-sign")
sys.path.insert(0, str(ROOT / "scripts"))
from profile_tools import load_json
from device_warmup import merge_reg_profile
from live_audience import enter_room
from mssdk_trust import apply_sdi_hex, is_trusted_sdi_token
profile = load_json(ROOT / "config/device_profile.json")
reg = {"device_id":"1782779405691530","install_id":"1782779405695626","openudid":profile.get("openudid",""),"cdid":profile.get("cdid",""),"device_token":""}
sdi = "3f185b8c8160f8562bdd7352accee14173d6d06c65d34310c0e59979591e8488c2085d6d1d510a02"
work = ROOT / "tmp" / ("reg_" + reg["device_id"])
work.mkdir(parents=True, exist_ok=True)
prof_path = work / "device_profile.json"
p = json.loads(json.dumps(profile)); p["deviceId"]=reg["device_id"]; p["installId"]=reg["install_id"]
prefs = dict(p.get("mssdkPrefs") or {}); prefs["1128-1128-sdi"]=sdi; p["mssdkPrefs"]=prefs
prof_path.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding="utf-8")
print("trusted", is_trusted_sdi_token(sdi), "applied", apply_sdi_hex(prof_path, sdi))
dev = merge_reg_profile(profile, reg); dev["mssdkPrefs"]=prefs
ids = {"device_id":reg["device_id"],"install_id":reg["install_id"],"openudid":reg["openudid"],"cdid":reg["cdid"],"device_token":""}
enter = enter_room(dev, "7699144929192184627", ids)
print(json.dumps(enter, ensure_ascii=False, indent=2))

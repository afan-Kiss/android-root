import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_runtime
collect_runtime.init()
import time
from profile_tools import load_json
from device_register import register_with_retry
from device_warmup import merge_reg_profile, full_warmup
from device_profile_pool import profile_for_worker
from live_square import fetch_feed_page, parse_room
prof_path = collect_runtime.SIGN_ROOT / "config" / "device_profile.json"
print("profile", prof_path, prof_path.is_file())
base = load_json(str(prof_path))
profile = profile_for_worker(base, 1)
print("registering...")
reg = register_with_retry(profile, retries=2, delay=3, timeout=30)
print("warmup...")
full_warmup(profile, reg, app_log_rounds=1, pause=0.5)
dev = merge_reg_profile(profile, reg)
ids = {"device_id": reg["device_id"], "install_id": reg["install_id"], "openudid": reg.get("openudid", ""), "cdid": reg.get("cdid", "")}
print("fetch feed...")
t0 = time.time()
body, hi = fetch_feed_page(dev, ids, "0", 20, 0)
print("elapsed", round(time.time() - t0, 2), "body", "yes" if body else "no")
if body:
    items = body.get("data") or []
    print("items", len(items))
    for it in items[:5]:
        r = parse_room(it)
        if r:
            print(" room", r["room_id"], "status", r.get("status"), "users", r.get("user_count"))

#!/usr/bin/env python3
"""Pure-protocol live boost: proxy register + full warmup + enter/ping (no profile pool by default)."""
from __future__ import annotations
import argparse, json, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(r"E:\douyin-android-sign")
sys.path.insert(0, str(ROOT / "scripts"))
from profile_tools import load_json
from device_register import register_with_retry
from device_warmup import merge_reg_profile
from mssdk_trust import trust_pipeline
from device_pool import load_pool, save_pool, add_device, DEFAULT_POOL
from live_audience import enter_room, ping_room, resolve_room_id
from proxy_utils import fetch_proxy, load_proxy_file

_print_lock = threading.Lock()


def profile_device_id(profile: dict) -> str:
    return str(profile.get("deviceId") or profile.get("device_id") or "")


def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def ids_from_row(row: dict) -> dict:
    return {
        "device_id": row["device_id"],
        "install_id": row["install_id"],
        "openudid": row.get("openudid", ""),
        "cdid": row.get("cdid", ""),
        "device_token": row.get("device_token") or "",
    }


def is_profile_device(did: str, profile: dict) -> bool:
    return str(did) == profile_device_id(profile)


def register_with_proxy_rotate(profile, retries=5, delay=8.0, proxies_list=None):
    last_err = None
    for i in range(retries):
        px = None
        if proxies_list:
            px = proxies_list[i % len(proxies_list)]
        if not px:
            px = fetch_proxy()
        try:
            reg = register_with_retry(profile, retries=2, delay=delay, proxies=px, timeout=25)
            reg["source"] = "register"
            return reg, px
        except Exception as e:
            last_err = e
            log(f"[reg] attempt {i+1}/{retries} failed: {e}")
            time.sleep(min(delay, 12))
    raise RuntimeError(last_err or "register failed")


def try_register_enter(profile, room_id, proxies_list, pool_path, app_log_rounds=3):
    try:
        reg, px = register_with_proxy_rotate(profile, retries=6, delay=8.0, proxies_list=proxies_list)
    except Exception as e:
        return None, {"ok": False, "reason": "register", "error": str(e)}
    if is_profile_device(reg["device_id"], profile):
        log(f"[warn] got profile device_id={reg['device_id']} (openudid collision?)")
    trust = trust_pipeline(profile, reg, proxies=px)
    if not trust.get("trust_ok"):
        log(f"[trust] blocker={trust.get('blocker')} did={reg['device_id']}")
    dev = merge_reg_profile(profile, reg)
    prof_path = Path(trust.get("profile") or "")
    if prof_path.is_file():
        reg_prof = load_json(prof_path)
        if reg_prof.get("mssdkPrefs"):
            dev["mssdkPrefs"] = reg_prof["mssdkPrefs"]
    ids = ids_from_row(reg)
    enter = enter_room(dev, room_id, ids, proxies=px)
    enter["trust"] = {k: trust.get(k) for k in ("sdi_source", "sdi_applied", "metasec") if k in trust}
    if enter.get("ok"):
        rows = load_pool(pool_path)
        rows = add_device(rows, reg, verified=True)
        save_pool(rows, pool_path)
        return reg, enter
    return reg, enter


def watch_device(profile, room_id, row, watch_sec, ping_interval, label, proxies=None):
    dev = merge_reg_profile(profile, row)
    ids = ids_from_row(row)
    enter = enter_room(dev, room_id, ids, proxies=proxies)
    if not enter.get("ok"):
        return {"ok": False, "label": label, "stage": "enter", "device_id": row["device_id"],
                "reason": enter.get("reason", "enter_failed")}
    log(f"[{label}] enter ok did={row['device_id']}")
    end = time.time() + max(watch_sec, 10)
    pings = 0
    wait = ping_interval or 15
    while time.time() < end:
        ping = ping_room(dev, room_id, ids, proxies=proxies)
        pings += 1
        if ping.get("ok"):
            wait = max(10, min(int(ping.get("next_ping") or wait), 300))
        time.sleep(min(wait, max(3, int(end - time.time()))))
    log(f"[{label}] done pings={pings}")
    return {"ok": True, "label": label, "device_id": row["device_id"], "pings": pings}


def run_register_worker(profile, room_id, proxies_list, watch_sec, ping_interval, label, pool_path, reg_delay, app_log_rounds):
    time.sleep(reg_delay)
    reg, enter = try_register_enter(profile, room_id, proxies_list, pool_path, app_log_rounds=app_log_rounds)
    if not reg:
        return {"ok": False, "label": label, "stage": "register", "reason": enter.get("reason", "register")}
    if not (enter and enter.get("ok")):
        return {"ok": False, "label": label, "stage": "enter", "device_id": reg["device_id"],
                "reason": enter.get("reason", "empty_body")}
    return watch_device(profile, room_id, reg, watch_sec, ping_interval, label)


def main():
    ap = argparse.ArgumentParser(description="Douyin android live boost (pure protocol)")
    ap.add_argument("--room", required=True, help="room_id or v.douyin.com short link")
    ap.add_argument("--proxies", default="")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--profile", default=str(ROOT / "config/device_profile.json"))
    ap.add_argument("--pool", default=str(DEFAULT_POOL))
    ap.add_argument("--watch", type=int, default=60)
    ap.add_argument("--ping-interval", type=int, default=12)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--reg-delay", type=float, default=8.0)
    ap.add_argument("--app-log-rounds", type=int, default=3)
    ap.add_argument("--demo", action="store_true", help="use profile device+SDI only (no register)")
    ap.add_argument("--register-only", action="store_true", help="only try new registrations")
    ap.add_argument("--use-pool", action="store_true", help="also use verified devices from pool")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    profile = load_json(args.profile)
    room_id = resolve_room_id(args.room)
    pool = load_pool(args.pool)
    verified = [r for r in pool if r.get("verified_enter") and r.get("device_id")]
    if args.demo:
        row = {
            "device_id": profile_device_id(profile),
            "install_id": str(profile.get("installId") or ""),
            "openudid": str(profile.get("openudid") or ""),
            "cdid": str(profile.get("cdid") or ""),
            "device_token": "",
            "verified_enter": True,
            "source": "demo",
        }
        if row["device_id"]:
            log(f"[boost] demo mode profile did={row['device_id']}")
            res = watch_device(profile, room_id, row, args.watch, args.ping_interval, "demo")
            out = ROOT / "tmp" / "boost_results.json"
            out.write_text(json.dumps([res], ensure_ascii=False, indent=2), encoding="utf-8")
            return 0 if res.get("ok") else 1
    proxies_list = load_proxy_file(args.proxies) if args.proxies else []
    while len(proxies_list) < args.count:
        p = fetch_proxy()
        if p:
            proxies_list.append(p)
        else:
            break
    log(f"[boost] room={room_id} pool_verified={len(verified)} targets={args.count} workers={args.workers}")
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 8))) as pool_ex:
        futs = []
        if args.use_pool and verified:
            for i, row in enumerate(verified[: max(1, min(len(verified), args.count))]):
                futs.append(pool_ex.submit(watch_device, profile, room_id, row, args.watch, args.ping_interval, f"p{i+1}"))
        reg_n = 0 if args.demo else (args.count if args.register_only else max(0, args.count - len(futs)))
        for i in range(reg_n):
            futs.append(pool_ex.submit(
                run_register_worker, profile, room_id, proxies_list,
                args.watch, args.ping_interval, f"v{i+1}", args.pool,
                args.reg_delay * (i % max(1, args.workers)), args.app_log_rounds,
            ))
        for f in as_completed(futs):
            results.append(f.result())
    ok_n = sum(1 for r in results if r.get("ok"))
    log(f"[boost] finished ok={ok_n}/{len(results)} pool_verified={len(load_pool(args.pool))}")
    out = ROOT / "tmp" / "boost_results.json"
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps({"ok": ok_n, "total": len(results), "room_id": room_id}, ensure_ascii=False))
    return 0 if ok_n else 1

if __name__ == "__main__":
    raise SystemExit(main())
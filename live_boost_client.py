#!/usr/bin/env python3
"""Multi-thread anonymous live audience booster: register device -> enter -> ping."""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import threading
import time
from pathlib import Path

import requests

APP_DIR = Path(__file__).resolve().parent
_sp = str(APP_DIR)
if _sp not in sys.path:
    sys.path.insert(0, _sp)

import runtime_paths

runtime_paths.init()

from device_pool import add_device, load_pool, save_pool, DEFAULT_POOL
from device_profile_pool import profile_for_worker, template_count
from guest_device import guest_from_pool_row, ids_from_reg, register_guest, watch_as_guest
from live_audience import resolve_room_id
from profile_tools import load_json
from proxy_utils import fetch_proxy

ROOT_SIGN = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))

_STAT_DEFAULTS = {
    "workers_alive": 0,
    "register_ok": 0,
    "register_fail": 0,
    "enter_ok": 0,
    "enter_fail": 0,
    "watch_ok": 0,
    "watch_fail": 0,
    "pings": 0,
}

_print_lock = threading.Lock()
_stats_lock = threading.Lock()
_reg_sem = threading.Semaphore(3)
_stats = dict(_STAT_DEFAULTS)
_stop = threading.Event()
_log_path: Path | None = None


def set_log_path(path: str | Path | None) -> None:
    global _log_path
    _log_path = Path(path) if path else None


def log(msg: str) -> None:
    with _print_lock:
        try:
            print(msg, flush=True)
        except Exception:
            pass
        if _log_path:
            try:
                with open(_log_path, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
            except Exception:
                pass


def bump(key: str, n: int = 1) -> None:
    with _stats_lock:
        _stats[key] = _stats.get(key, 0) + n


def default_profile_path() -> Path:
    return ROOT_SIGN / "config" / "device_profile.json"


def profile_guest_row(profile: dict) -> dict:
    return {
        "device_id": str(profile.get("deviceId") or ""),
        "install_id": str(profile.get("installId") or ""),
        "openudid": str(profile.get("openudid") or profile.get("androidId") or ""),
        "cdid": str(profile.get("cdid") or ""),
        "device_token": "",
        "verified_enter": True,
        "source": "profile",
    }


def _acquire_proxy(proxy_api: str, worker_id: int) -> dict | None:
    if not proxy_api:
        return None
    px = fetch_proxy(proxy_api)
    if px:
        log("[w%02d] proxy %s" % (worker_id, px.get("http", "")))
    return px


def worker_register(
    worker_id: int,
    base_profile: dict,
    room_id: str,
    machine_id: str,
    stop_at: float,
    watch_sec: int,
    ping_iv: int,
    reg_retries: int,
    proxy_api: str,
    pool_path: Path,
    trust: bool,
    phone_sdi: bool,
) -> None:
    bump("workers_alive")
    try:
        if _stop.is_set() or time.time() >= stop_at:
            return
        profile = profile_for_worker(base_profile, worker_id, machine_id)
        time.sleep(random.uniform(1.0, 3.0) + (worker_id % 8) * 0.4)
        proxies = _acquire_proxy(proxy_api, worker_id)
        reg = None
        for attempt in range(1, reg_retries + 1):
            if _stop.is_set():
                return
            if attempt > 1 and proxy_api:
                proxies = _acquire_proxy(proxy_api, worker_id) or proxies
            with _reg_sem:
                try:
                    guest = register_guest(
                        profile,
                        proxies=proxies,
                        reg_retries=3,
                        reg_delay=6.0,
                        warmup=True,
                        app_log_rounds=2,
                        trust=trust,
                        phone_sdi=phone_sdi,
                    )
                    reg = guest["reg"]
                    bump("register_ok")
                    break
                except Exception as e:
                    log("[w%02d] register %s/%s fail: %s" % (worker_id, attempt, reg_retries, e))
            time.sleep(min(5.0 * attempt, 25.0))
        if not reg:
            bump("register_fail")
            return
        dev = guest["dev"]
        ids = ids_from_reg(reg)
        model = profile.get("build", {}).get("model", "?")
        dname = profile.get("_device_name", "")
        log("[w%02d] did=%s model=%s (%s) trust=%s" % (
            worker_id, ids["device_id"], model, dname,
            (guest.get("trust") or {}).get("sdi_source", "none"),
        ))
        res = watch_as_guest(dev, room_id, ids, duration=watch_sec, ping_interval=ping_iv, proxies=proxies)
        if res.get("ok"):
            bump("enter_ok")
            bump("watch_ok")
            bump("pings", int(res.get("pings") or 0))
            rows = load_pool(pool_path)
            save_pool(add_device(rows, {**reg, "source": "boost_register"}, verified=True), pool_path)
            log("[w%02d] watch ok pings=%s" % (worker_id, res.get("pings")))
        else:
            bump("enter_fail")
            bump("watch_fail")
            reason = (res.get("enter") or {}).get("reason") or res.get("stage")
            log("[w%02d] enter/watch fail: %s" % (worker_id, reason))
    finally:
        bump("workers_alive", -1)


def worker_pool(
    worker_id: int,
    base_profile: dict,
    row: dict,
    room_id: str,
    stop_at: float,
    watch_sec: int,
    ping_iv: int,
    proxy_api: str,
) -> None:
    bump("workers_alive")
    try:
        if _stop.is_set() or time.time() >= stop_at:
            return
        dev, ids = guest_from_pool_row(base_profile, row)
        proxies = _acquire_proxy(proxy_api, worker_id)
        log("[w%02d] pool did=%s" % (worker_id, ids["device_id"]))
        res = watch_as_guest(dev, room_id, ids, duration=watch_sec, ping_interval=ping_iv, proxies=proxies)
        if res.get("ok"):
            bump("enter_ok")
            bump("watch_ok")
            bump("pings", int(res.get("pings") or 0))
            log("[w%02d] pool watch ok pings=%s" % (worker_id, res.get("pings")))
        else:
            bump("enter_fail")
            bump("watch_fail")
            log("[w%02d] pool fail: %s" % (worker_id, (res.get("enter") or {}).get("reason")))
    finally:
        bump("workers_alive", -1)


def print_stats_loop(stop_at: float, interval: float = 12.0) -> None:
    while time.time() < stop_at and not _stop.is_set():
        time.sleep(interval)
        with _stats_lock:
            s = dict(_stats)
        left = max(0, int(stop_at - time.time()))
        log("[stats] alive=%s reg_ok=%s enter_ok=%s fail=%s pings=%s left=%ss" % (
            s["workers_alive"], s["register_ok"], s["enter_ok"],
            s["enter_fail"], s["pings"], left,
        ))


def run_boost(
    room: str,
    workers: int = 10,
    duration: int = 300,
    watch_sec: int = 120,
    ping_interval: int = 12,
    profile: str = "",
    machine_id: str = "",
    mode: str = "auto",
    pool_path: str = "",
    reg_retries: int = 6,
    proxy_api: str = "",
    trust: bool = False,
    phone_sdi: bool = False,
) -> int:
    global _stats
    _stop.clear()
    with _stats_lock:
        _stats = dict(_STAT_DEFAULTS)

    try:
        import collect_runtime
        set_log_path(collect_runtime._exe_dir() / "boost_client.log")
    except Exception:
        set_log_path(APP_DIR / "data" / "boost_client.log")

    prof_path = profile or str(default_profile_path())
    if not Path(prof_path).is_file():
        log("[error] profile not found: %s" % prof_path)
        return 1

    base_profile = load_json(prof_path)
    room_id = resolve_room_id(room)
    mid = machine_id or socket.gethostname()
    pool_file = Path(pool_path or str(DEFAULT_POOL))
    pool_rows = [r for r in load_pool(pool_file) if r.get("verified_enter") and r.get("device_id")]
    proxy_api = (proxy_api or os.environ.get("COLLECT_PROXY_API", "")).strip()
    stop_at = time.time() + max(duration, 30)

    log("[start] room=%s workers=%s mode=%s watch=%ss templates=%s pool=%s proxy=%s" % (
        room_id, workers, mode, watch_sec, template_count(), len(pool_rows), "on" if proxy_api else "off",
    ))

    threads: list[threading.Thread] = []
    threading.Thread(target=print_stats_loop, args=(stop_at,), daemon=True).start()

    if mode in ("demo", "profile"):
        row = profile_guest_row(base_profile)
        if not row["device_id"]:
            log("[error] profile has no deviceId")
            return 1
        threads.append(threading.Thread(
            target=worker_pool,
            args=(1, base_profile, row, room_id, stop_at, watch_sec, ping_interval, proxy_api),
            name="boost-demo",
            daemon=True,
        ))
    elif mode == "pool":
        if not pool_rows:
            log("[error] pool empty, use --mode register or demo")
            return 1
        for i, row in enumerate(pool_rows[:workers]):
            threads.append(threading.Thread(
                target=worker_pool,
                args=(i + 1, base_profile, row, room_id, stop_at, watch_sec, ping_interval, proxy_api),
                name="boost-p%02d" % (i + 1),
                daemon=True,
            ))
    elif mode == "register":
        for i in range(workers):
            threads.append(threading.Thread(
                target=worker_register,
                args=(i + 1, base_profile, room_id, mid, stop_at, watch_sec, ping_interval,
                      reg_retries, proxy_api, pool_file, trust, phone_sdi),
                name="boost-r%02d" % (i + 1),
                daemon=True,
            ))
    else:
        use_pool = min(len(pool_rows), max(0, workers // 3))
        reg_n = max(1, workers - use_pool)
        if row := profile_guest_row(base_profile):
            if row.get("device_id") and use_pool == 0 and reg_n == workers:
                threads.append(threading.Thread(
                    target=worker_pool,
                    args=(1, base_profile, row, room_id, stop_at, watch_sec, ping_interval, proxy_api),
                    name="boost-demo",
                    daemon=True,
                ))
                reg_n = max(0, workers - 1)
        for i, row in enumerate(pool_rows[:use_pool]):
            threads.append(threading.Thread(
                target=worker_pool,
                args=(i + 1, base_profile, row, room_id, stop_at, watch_sec, ping_interval, proxy_api),
                name="boost-p%02d" % (i + 1),
                daemon=True,
            ))
        for i in range(reg_n):
            threads.append(threading.Thread(
                target=worker_register,
                args=(use_pool + i + 1, base_profile, room_id, mid, stop_at, watch_sec, ping_interval,
                      reg_retries, proxy_api, pool_file, trust, phone_sdi),
                name="boost-r%02d" % (i + 1),
                daemon=True,
            ))

    try:
        for i, t in enumerate(threads):
            t.start()
            if i + 1 < len(threads):
                time.sleep(0.2)
        while time.time() < stop_at and not _stop.is_set():
            alive = sum(1 for t in threads if t.is_alive())
            if alive == 0:
                break
            time.sleep(1.0)
        _stop.set()
        for t in threads:
            t.join(timeout=5.0)
    except KeyboardInterrupt:
        log("[stop] interrupted")
        _stop.set()

    with _stats_lock:
        summary = dict(_stats)
    out_dir = Path(os.environ.get("COLLECT_DATA", str(APP_DIR / "data")))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / ("boost_result_%s.json" % int(time.time()))
    payload = {
        "room_id": room_id,
        "mode": mode,
        "workers": workers,
        "watch_sec": watch_sec,
        "stats": summary,
        "pool_verified": len(load_pool(pool_file)),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    log("[done] enter_ok=%s fail=%s pings=%s pool=%s -> %s" % (
        summary.get("enter_ok"), summary.get("enter_fail"), summary.get("pings"),
        payload["pool_verified"], out.name,
    ))
    return 0 if summary.get("enter_ok", 0) > 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Douyin anonymous live audience booster")
    ap.add_argument("--room", required=True, help="room_id or live.douyin.com link")
    ap.add_argument("--workers", type=int, default=10, help="concurrent guest workers")
    ap.add_argument("--duration", type=int, default=600, help="total run seconds")
    ap.add_argument("--watch", type=int, default=120, help="seconds to stay in room per guest")
    ap.add_argument("--ping-interval", type=int, default=12)
    ap.add_argument("--profile", default="")
    ap.add_argument("--pool", default="")
    ap.add_argument("--machine-id", default="")
    ap.add_argument("--mode", choices=("auto", "demo", "profile", "pool", "register"), default="auto")
    ap.add_argument("--reg-retries", type=int, default=6)
    ap.add_argument("--proxy-api", default="")
    ap.add_argument("--trust", action="store_true", help="run MSSDK trust after register (needs phone/unidbg)")
    ap.add_argument("--phone-sdi", action="store_true", help="enable phone SDI capture in trust pipeline")
    args = ap.parse_args()
    return run_boost(
        room=args.room,
        workers=max(1, min(args.workers, 100)),
        duration=max(30, args.duration),
        watch_sec=max(15, args.watch),
        ping_interval=max(5, args.ping_interval),
        profile=args.profile,
        machine_id=args.machine_id,
        mode=args.mode,
        pool_path=args.pool,
        reg_retries=args.reg_retries,
        proxy_api=args.proxy_api or os.environ.get("COLLECT_PROXY_API", ""),
        trust=args.trust or args.phone_sdi,
        phone_sdi=args.phone_sdi,
    )


if __name__ == "__main__":
    raise SystemExit(main())

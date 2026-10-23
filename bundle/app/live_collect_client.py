#!/usr/bin/env python3
"""Android live feed collector: register device per worker, report to central server."""
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
ROOT_SIGN = Path(os.environ.get("DOUYIN_SIGN_ROOT", r"E:\douyin-android-sign"))
_sp = str(APP_DIR)
if _sp not in sys.path:
    sys.path.insert(0, _sp)

from device_register import register_with_retry
from device_warmup import full_warmup, merge_reg_profile
from live_square import fetch_feed_page, parse_room
from profile_tools import load_json
from device_profile_pool import profile_for_worker, template_count
from urllib.parse import urlparse

DEFAULT_SERVER = "http://39.108.179.146:9909"
DEFAULT_PROXY_API = (
    "https://getip.huashengdaili.com/servers.php?"
    "session=U94feb8410923121918--483daffff81cf261824e9615375156fa"
    "&time=1&count=1&type=text&pw=no&protocol=http&separator=1&iptype=tunnel&format=null&dev=web"
)


def _parse_proxy_line(line: str) -> dict[str, str] | None:
    line = (line or "").strip()
    if not line or line.startswith("#") or line.startswith("{"):
        return None
    if "://" in line:
        url = line
    elif line.count(":") == 3:
        h, p, u, pw = line.split(":", 3)
        url = "http://%s:%s@%s:%s" % (u, pw, h, p)
    elif line.count(":") == 1:
        h, p = line.split(":", 1)
        url = "http://%s:%s" % (h, p)
    else:
        return None
    parsed = urlparse(url)
    if not parsed.hostname:
        return None
    if not parsed.port:
        port = 443 if parsed.scheme == "https" else 80
        host = parsed.hostname
        auth = ""
        if parsed.username:
            auth = "%s:%s@" % (parsed.username, parsed.password or "")
        url = "%s://%s%s:%s" % (parsed.scheme or "http", auth, host, port)
    return {"http": url, "https": url}


def fetch_proxy(api_url: str | None = None, timeout: int = 15) -> dict[str, str] | None:
    url = (api_url or os.environ.get("COLLECT_PROXY_API") or "").strip()
    if not url:
        return None
    try:
        text = requests.get(url, timeout=timeout).text.strip()
        if not text or text.startswith("{"):
            return None
        return _parse_proxy_line(text.splitlines()[0].strip())
    except Exception:
        return None

_STAT_DEFAULTS = {
    "workers_alive": 0, "pages": 0, "raw_items": 0, "local_unique": 0,
    "reported": 0, "report_batches": 0, "register_ok": 0, "register_fail": 0,
    "feed_errors": 0, "report_errors": 0, "warmup_ok": 0,
}


def default_profile_path() -> Path:
    root = Path(os.environ.get("DOUYIN_SIGN_ROOT", str(ROOT_SIGN)))
    return root / "config" / "device_profile.json"

_print_lock = threading.Lock()
_stats_lock = threading.Lock()
_reg_sem = threading.Semaphore(3)
_stats = dict(_STAT_DEFAULTS)
_local_seen: set[str] = set()
_buffer_lock = threading.Lock()
_buffer: list[dict] = []
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


def _reset_run_state() -> None:
    _stop.clear()
    with _stats_lock:
        _stats.clear()
        _stats.update(_STAT_DEFAULTS)
        _local_seen.clear()
    with _buffer_lock:
        _buffer.clear()


def _acquire_proxy(worker_id: int, proxy_api: str) -> dict | None:
    if not proxy_api:
        return None
    px = fetch_proxy(proxy_api)
    if px:
        log("[w%02d] proxy %s" % (worker_id, px.get("http", "")))
        return px
    log("[w%02d] proxy fail: api returned empty (check whitelist IP)" % worker_id)
    return None


def register_device(profile: dict, worker_id: int, reg_retries: int, proxy_api: str = "") -> tuple[dict | None, dict | None]:
    time.sleep(random.uniform(1.0, 4.0) + (worker_id % 10) * 0.5)
    proxies = _acquire_proxy(worker_id, proxy_api)
    for attempt in range(1, reg_retries + 1):
        if _stop.is_set():
            return None, proxies
        if attempt > 1 and proxy_api:
            proxies = _acquire_proxy(worker_id, proxy_api) or proxies
        with _reg_sem:
            try:
                reg = register_with_retry(profile, retries=4, delay=6.0, timeout=30, proxies=proxies)
                bump("register_ok")
                return reg, proxies
            except Exception as e:
                log("[w%02d] register attempt %s/%s failed: %s" % (worker_id, attempt, reg_retries, e))
        time.sleep(min(6.0 * attempt, 30.0))
    bump("register_fail")
    return None, proxies


_BATCH_LIMIT = 500


def _post_batch(server: str, machine_id: str, batch: list[dict]) -> tuple[bool, str]:
    url = server.rstrip("/") + "/api/rooms"
    payload = {"machine_id": machine_id, "rooms": batch}
    last_err = ""
    for attempt in range(3):
        try:
            r = requests.post(url, json=payload, timeout=20)
            try:
                data = r.json() if r.text else {}
            except ValueError:
                data = {}
            if r.status_code == 200 and data.get("ok"):
                bump("reported", len(batch))
                bump("report_batches")
                log("[report] sent=%s inserted=%s updated=%s total=%s" % (
                    len(batch), data.get("inserted"), data.get("updated"), data.get("total")))
                return True, ""
            last_err = "http=%s %s" % (r.status_code, (r.text or "")[:200])
        except Exception as e:
            last_err = str(e)
        time.sleep(1.5 * (attempt + 1))
    return False, last_err


def flush_buffer(server: str, machine_id: str, force: bool = False) -> None:
    with _buffer_lock:
        if not _buffer:
            return
        if len(_buffer) < 10 and not force:
            return
        batch = _buffer[:]
        _buffer.clear()
    if not batch:
        return
    failed: list[dict] = []
    for i in range(0, len(batch), _BATCH_LIMIT):
        chunk = batch[i:i + _BATCH_LIMIT]
        ok, err = _post_batch(server, machine_id, chunk)
        if not ok:
            failed.extend(chunk)
            bump("report_errors")
            log("[report] fail after retries: %s" % err)
    if failed:
        with _buffer_lock:
            _buffer.extend(failed)


def enqueue_room(room: dict) -> bool:
    rid = str(room.get("room_id") or "").strip()
    if not rid:
        return False
    status = room.get("status")
    if status is not None:
        try:
            if int(status) != 2:
                return False
        except (TypeError, ValueError):
            return False
    with _stats_lock:
        if rid in _local_seen:
            return False
        _local_seen.add(rid)
        _stats["local_unique"] = _stats.get("local_unique", 0) + 1
    uc = room.get("user_count")
    try:
        uc = int(uc) if uc is not None else None
    except (TypeError, ValueError):
        uc = None
    with _buffer_lock:
        _buffer.append({"live_id": rid, "user_count": uc})
    return True


def worker(worker_id, base_profile, server, machine_id, stop_at, pause, count, reg_retries, warmup, proxy_api: str = ""):
    bump("workers_alive")
    try:
        profile = profile_for_worker(base_profile, worker_id)
        reg, proxies = register_device(profile, worker_id, reg_retries, proxy_api)
        if not reg:
            return
        if warmup:
            try:
                w = full_warmup(profile, reg, proxies=proxies, app_log_rounds=1, pause=0.8)
                if w.get("ok"):
                    bump("warmup_ok")
            except Exception as e:
                log("[w%02d] warmup warn: %s" % (worker_id, e))
        dev = merge_reg_profile(profile, reg)
        ids = {
            "device_id": reg["device_id"], "install_id": reg["install_id"],
            "openudid": reg.get("openudid", ""), "cdid": reg.get("cdid", ""),
        }
        model = profile.get("build", {}).get("model", "?")
        dname = profile.get("_device_name", "")
        log("[w%02d] ready did=%s model=%s (%s)" % (worker_id, ids["device_id"], model, dname))
        max_time, host_idx, pages, empty_streak = "0", worker_id % 3, 0, 0
        while time.time() < stop_at and not _stop.is_set():
            if pages == 0:
                log("[w%02d] fetching feed..." % worker_id)
            body, host_idx = fetch_feed_page(dev, ids, max_time, count, host_idx, proxies=proxies)
            pages += 1
            bump("pages")
            if not body:
                bump("feed_errors")
                empty_streak += 1
                if empty_streak <= 3 or empty_streak % 5 == 0:
                    log("[w%02d] feed empty streak=%s" % (worker_id, empty_streak))
                time.sleep(min(1.2 + empty_streak * 0.2, 5.0))
                if empty_streak >= 5:
                    max_time = "0"
                    empty_streak = 0
                continue
            empty_streak = 0
            extra = body.get("extra") or {}
            if extra.get("max_time") is not None:
                max_time = str(extra.get("max_time"))
            items = body.get("data") or []
            bump("raw_items", len(items))
            new_n = 0
            for item in items:
                room = parse_room(item)
                if room and enqueue_room(room):
                    new_n += 1
            if new_n == 0 and pages % 12 == 0:
                max_time = "0"
            if pages == 1 or pages % 5 == 0 or new_n:
                log("[w%02d] page=%s items=%s new=%s" % (worker_id, pages, len(items), new_n))
            if pages % 3 == 0:
                flush_buffer(server, machine_id)
            time.sleep(pause + random.uniform(0, pause * 0.5))
        flush_buffer(server, machine_id, force=True)
        log("[w%02d] stopped pages=%s" % (worker_id, pages))
    finally:
        bump("workers_alive", -1)


def reporter(server, machine_id, stop_at, interval):
    while time.time() < stop_at and not _stop.is_set():
        flush_buffer(server, machine_id, force=True)
        time.sleep(interval)


def print_stats_loop(stop_at, interval=15.0):
    while time.time() < stop_at and not _stop.is_set():
        time.sleep(interval)
        with _stats_lock:
            s = dict(_stats)
        left = max(0, int(stop_at - time.time()))
        log("[stats] workers=%s pages=%s unique=%s reported=%s reg_ok=%s warmup=%s feed_err=%s left=%ss" % (
            s["workers_alive"], s["pages"], s["local_unique"], s["reported"],
            s["register_ok"], s["warmup_ok"], s["feed_errors"], left))


def fetch_server_stats(server):
    try:
        r = requests.get(server.rstrip("/") + "/api/stats", timeout=10)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}



def run_collect(
    server: str = DEFAULT_SERVER,
    workers: int = 50,
    duration: int = 1800,
    profile: str = "",
    pause: float = 0.12,
    count: int = 20,
    machine_id: str = "",
    report_interval: float = 5.0,
    reg_retries: int = 8,
    warmup: bool = True,
    proxy_api: str = "",
) -> int:
    _reset_run_state()
    try:
        import collect_runtime
        set_log_path(collect_runtime._exe_dir() / "client.log")
    except Exception:
        pass
    workers = max(1, min(int(workers), 200))
    duration = max(60, int(duration))
    prof_path = profile or str(default_profile_path())
    if not Path(prof_path).is_file():
        log("[error] profile not found: %s" % prof_path)
        return 1
    base_profile = load_json(prof_path)
    mid = machine_id or socket.gethostname()
    stop_at = time.time() + max(duration, 60)
    proxy_api = (proxy_api or os.environ.get("COLLECT_PROXY_API", "")).strip()
    log("[start] server=%s workers=%s duration=%ss machine=%s templates=%s proxy=%s" % (
        server, workers, duration, mid, template_count(), "on" if proxy_api else "off"))
    try:
        health = requests.get(server.rstrip("/") + "/api/health", timeout=8).json()
        if not health.get("ok"):
            log("[warn] server health odd: %s" % health)
    except Exception as e:
        log("[error] cannot reach server %s: %s" % (server, e))
        return 1
    threading.Thread(target=reporter, args=(server, mid, stop_at, report_interval), daemon=True).start()
    threading.Thread(target=print_stats_loop, args=(stop_at,), daemon=True).start()

    def _run_one(wid: int) -> None:
        try:
            worker(wid, base_profile, server, mid, stop_at, pause, count, reg_retries, warmup, proxy_api)
        except Exception as e:
            log("[worker] crash w%02d: %s" % (wid, e))

    threads: list[threading.Thread] = []
    try:
        for i in range(workers):
            t = threading.Thread(
                target=_run_one, args=(i + 1,), name="collect-w%02d" % (i + 1), daemon=True,
            )
            threads.append(t)
        for i, t in enumerate(threads):
            t.start()
            if i + 1 < workers:
                time.sleep(0.15)
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        log("[stop] interrupted")
        _stop.set()
    _stop.set()
    flush_buffer(server, mid, force=True)
    srv = fetch_server_stats(server)
    with _stats_lock:
        local = dict(_stats)
    data_dir = Path(os.environ.get("COLLECT_DATA", str(APP_DIR / "data")))
    out = data_dir / ("collect_result_%s.json" % int(time.time()))
    out.parent.mkdir(parents=True, exist_ok=True)
    summary = {"machine_id": mid, "duration_sec": duration, "workers": workers, "client": local, "server": srv}
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    log("[done] server_unique=%s local_unique=%s" % (srv.get("unique_rooms"), local.get("local_unique")))
    if local.get("register_ok", 0) == 0 and workers > 0:
        return 1
    unique_n = int(local.get("local_unique", 0) or 0)
    reported_n = int(local.get("reported", 0) or 0)
    if unique_n > 0 and reported_n < unique_n:
        with _buffer_lock:
            pending = len(_buffer)
        log("[warn] incomplete report unique=%s reported=%s pending=%s" % (unique_n, reported_n, pending))
        return 1
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description="Live feed collector client")
    ap.add_argument("--server", default=DEFAULT_SERVER)
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--duration", type=int, default=1800)
    ap.add_argument("--profile", default="")
    ap.add_argument("--pause", type=float, default=0.12)
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--machine-id", default="")
    ap.add_argument("--report-interval", type=float, default=5.0)
    ap.add_argument("--reg-retries", type=int, default=8)
    ap.add_argument("--no-warmup", action="store_true")
    ap.add_argument("--proxy-api", default="", help="huasheng proxy api url")
    args = ap.parse_args()
    return run_collect(
        server=args.server,
        workers=args.workers,
        duration=args.duration,
        profile=args.profile,
        pause=args.pause,
        count=args.count,
        machine_id=args.machine_id,
        report_interval=args.report_interval,
        reg_retries=args.reg_retries,
        warmup=not args.no_warmup,
        proxy_api=args.proxy_api or os.environ.get("COLLECT_PROXY_API", ""),
    )


if __name__ == "__main__":
    raise SystemExit(main())
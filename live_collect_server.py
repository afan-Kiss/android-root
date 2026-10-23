#!/usr/bin/env python3
"""Central server: receive live rooms, dedupe by live_id, store to local SQLite."""
from __future__ import annotations

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from live_collect_store import make_store
from live_collect_web import DASHBOARD_HTML

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9909
MAX_BODY = 2 * 1024 * 1024
MAX_ROOMS_PER_BATCH = 500


class CollectHandler(BaseHTTPRequestHandler):
    db: object
    user_id: str = "admin"

    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (time.strftime("%H:%M:%S"), fmt % args), flush=True)

    def _write_body(self, raw: bytes) -> None:
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code: int, body: dict) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self._write_body(raw)

    def _html(self, code: int, html: str) -> None:
        raw = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self._write_body(raw)

    def _read_json(self) -> dict | list | None:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return None
        if n > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/dashboard"):
            self._html(200, DASHBOARD_HTML)
            return
        if path == "/api/health":
            self._json(200, {"ok": True, "service": "live_collect_server"})
            return
        if path == "/api/stats":
            try:
                st = self.db.stats()
                st["ok"] = True
                self._json(200, st)
            except Exception as e:
                self._json(500, {"ok": False, "error": "stats_failed", "detail": str(e)})
            return
        if path == "/api/rooms/list":
            qs = parse_qs(parsed.query)
            try:
                page = int((qs.get("page") or ["1"])[0])
                limit = int((qs.get("limit") or ["50"])[0])
            except (TypeError, ValueError):
                self._json(400, {"ok": False, "error": "invalid_page_or_limit"})
                return
            if page < 1 or limit < 1 or limit > 200:
                self._json(400, {"ok": False, "error": "invalid_page_or_limit"})
                return
            q = (qs.get("q") or [""])[0]
            try:
                data = self.db.list_rooms(page=page, limit=limit, q=q)
                data["ok"] = True
                self._json(200, data)
            except Exception as e:
                self._json(500, {"ok": False, "error": "list_failed", "detail": str(e)})
            return
        self._json(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/rooms":
            self._json(404, {"ok": False, "error": "not_found"})
            return
        body = self._read_json()
        if body is None:
            n = int(self.headers.get("Content-Length") or 0)
            err = "body_too_large" if n > MAX_BODY else "invalid_json"
            self._json(400, {"ok": False, "error": err})
            return
        rooms = body if isinstance(body, list) else (body.get("rooms") if isinstance(body, dict) else None)
        if not isinstance(rooms, list):
            self._json(400, {"ok": False, "error": "rooms_must_be_list"})
            return
        if len(rooms) > MAX_ROOMS_PER_BATCH:
            self._json(400, {"ok": False, "error": "too_many_rooms", "max": MAX_ROOMS_PER_BATCH})
            return
        machine = body.get("machine_id", "") if isinstance(body, dict) else ""
        try:
            result = self.db.upsert_rooms(rooms, user_id=self.user_id)
            result["ok"] = True
            result["received"] = len(rooms)
            if machine:
                result["machine_id"] = machine
            self._json(200, result)
        except Exception as e:
            self._json(500, {"ok": False, "error": "upsert_failed", "detail": str(e)})


def main() -> int:
    ap = argparse.ArgumentParser(description="Live room collect server")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--db", default="")
    ap.add_argument("--user-id", default="admin")
    ap.add_argument("--mysql", action="store_true", help="use MySQL backend")
    args = ap.parse_args()

    if args.mysql:
        import os
        os.environ["COLLECT_BACKEND"] = "mysql"
    db = make_store(args.db or None)
    CollectHandler.db = db
    CollectHandler.user_id = args.user_id

    class _ReuseHTTPServer(ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = _ReuseHTTPServer((args.host, args.port), CollectHandler)
    print("[server] listening http://%s:%s" % (args.host, args.port), flush=True)
    print("[server] db=%s" % db.path, flush=True)
    print("[server] dashboard http://127.0.0.1:%s/" % args.port, flush=True)
    print("[server] stats http://127.0.0.1:%s/api/stats" % args.port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
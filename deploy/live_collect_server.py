#!/usr/bin/env python3
"""Central server: receive live rooms, dedupe by live_id, store to local SQLite."""
from __future__ import annotations

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from live_collect_store import make_store

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9909
MAX_BODY = 2 * 1024 * 1024


class CollectHandler(BaseHTTPRequestHandler):
    db: object
    user_id: str = "admin"

    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (time.strftime("%H:%M:%S"), fmt % args), flush=True)

    def _json(self, code: int, body: dict) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

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
        path = urlparse(self.path).path
        if path in ("/", "/api/health"):
            self._json(200, {"ok": True, "service": "live_collect_server"})
            return
        if path == "/api/stats":
            st = self.db.stats()
            st["ok"] = True
            self._json(200, st)
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
        machine = body.get("machine_id", "") if isinstance(body, dict) else ""
        result = self.db.upsert_rooms(rooms, user_id=self.user_id)
        result["ok"] = True
        result["received"] = len(rooms)
        if machine:
            result["machine_id"] = machine
        self._json(200, result)


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

    server = ThreadingHTTPServer((args.host, args.port), CollectHandler)
    print("[server] listening http://%s:%s" % (args.host, args.port), flush=True)
    print("[server] db=%s" % db.path, flush=True)
    print("[server] stats http://127.0.0.1:%s/api/stats" % args.port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
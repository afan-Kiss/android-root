from pathlib import Path
ROOT = Path(r"E:\我的源码目录\安卓ROOT")
srv = ROOT / "live_collect_server.py"
st = srv.read_text(encoding="utf-8")
st = st.replace("from live_collect_db import DEFAULT_DB, LiveCollectDB", "from live_collect_store import make_store")
st = st.replace("DEFAULT_PORT = 8787", "DEFAULT_PORT = 9909")
st = st.replace("    db: LiveCollectDB", "    db: object")
st = st.replace('ap.add_argument("--db", default=str(DEFAULT_DB))', 'ap.add_argument("--db", default="")')
st = st.replace(
    '    args = ap.parse_args()\n\n    db = LiveCollectDB(args.db)',
    '    ap.add_argument("--mysql", action="store_true", help="use MySQL backend")\n    args = ap.parse_args()\n\n    if args.mysql:\n        import os\n        os.environ["COLLECT_BACKEND"] = "mysql"\n    db = make_store(args.db or None)',
)
srv.write_text(st, encoding="utf-8")
for name in ("live_collect_mysql.py", "live_collect_store.py"):
    src = ROOT / name
    if src.read_bytes().count(b"\x00"):
        raise SystemExit(f"corrupt {name}")
    (ROOT / "deploy" / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
(ROOT / "deploy" / "live_collect_db.py").write_text((ROOT / "live_collect_db.py").read_text(encoding="utf-8"), encoding="utf-8")
(ROOT / "deploy" / "live_collect_server.py").write_text(st, encoding="utf-8")
print("ok", srv.read_bytes().count(b"\x00"))
from pathlib import Path
ROOT = Path(r"E:\我的源码目录\安卓ROOT")
db = ROOT / "live_collect_db.py"
text = db.read_text(encoding="utf-8")
old = '''APP_DIR = Path(__file__).resolve().parent
DEFAULT_DB = Path(os.environ.get("COLLECT_DATA", str(APP_DIR / "data"))) / "live_collect.db"'''
new = '''APP_DIR = Path(__file__).resolve().parent


def resolve_db_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    try:
        import collect_runtime
        data_dir = collect_runtime.DATA_DIR
        if data_dir:
            return Path(data_dir) / "live_collect.db"
    except Exception:
        pass
    return Path(os.environ.get("COLLECT_DATA", str(APP_DIR / "data"))) / "live_collect.db"'''
text = text.replace(old, new)
text = text.replace(
    "    def __init__(self, path: str | Path = DEFAULT_DB) -> None:\n        self.path = Path(path)",
    "    def __init__(self, path: str | Path | None = None) -> None:\n        self.path = resolve_db_path(path)",
)
db.write_text(text, encoding="utf-8")
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
for name in ("live_collect_db.py", "live_collect_server.py", "live_collect_mysql.py", "live_collect_store.py"):
    nul = (ROOT / name).read_bytes().count(b"\x00")
    print(name, nul)
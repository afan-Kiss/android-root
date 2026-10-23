from pathlib import Path
p = Path(r"E:\我的源码目录\安卓ROOT\live_collect_db.py")
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text("print(1)\n", encoding="utf-8")
print("ok", open(p,"rb").read(10))
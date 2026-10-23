from pathlib import Path
p = Path(r"E:\我的源码目录\安卓ROOT\live_collect_client.py")
t = p.read_text(encoding="utf-8")
t = t.replace('DEFAULT_SERVER = "http://127.0.0.1:8787"', 'DEFAULT_SERVER = "http://39.108.179.146:9909"')
p.write_text(t, encoding="utf-8")
print("nul", p.read_bytes().count(b"\x00"))
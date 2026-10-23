#!/usr/bin/env python3
"""Live collect client - Win32 native UI, worker runs in subprocess."""
from __future__ import annotations

import configparser
import os
import subprocess
import sys
from pathlib import Path

import collect_runtime

collect_runtime.init()

DEFAULT_SERVER = "http://39.108.179.146:9909"
DEFAULT_PROXY = (
    "https://getip.huashengdaili.com/servers.php?"
    "session=U94feb8410923121918--483daffff81cf261824e9615375156fa"
    "&time=1&count=1&type=text&pw=no&protocol=http&separator=1&iptype=tunnel&format=null&dev=web"
)

ID_START = 1001
ID_SERVER = 1002
ID_WORKERS = 1003
ID_MINUTES = 1004
ID_LOG = 1005
WM_TIMER = 0x0113
TIMER_ID = 1
EM_LIMITTEXT = 0x00C1


def _exe_dir() -> Path:
    return collect_runtime._exe_dir()


def _ini_path() -> Path:
    return _exe_dir() / "client.ini"


def _log_path() -> Path:
    return _exe_dir() / "client.log"


def load_config() -> dict[str, str]:
    ini = _ini_path()
    cfg = configparser.ConfigParser()
    defaults = {
        "server": DEFAULT_SERVER,
        "workers": "1",
        "minutes": "30",
        "proxy_api": DEFAULT_PROXY,
    }
    if ini.is_file():
        cfg.read(ini, encoding="utf-8")
    sec = cfg["collect"] if cfg.has_section("collect") else {}
    out = {k: sec.get(k, defaults[k]) for k in defaults}
    if not ini.is_file():
        save_config(out)
    return out


def save_config(data: dict[str, str]) -> None:
    cfg = configparser.ConfigParser()
    cfg["collect"] = {
        "server": data.get("server", DEFAULT_SERVER),
        "workers": data.get("workers", "1"),
        "minutes": data.get("minutes", "30"),
        "proxy_api": data.get("proxy_api", DEFAULT_PROXY),
    }
    with open(_ini_path(), "w", encoding="utf-8") as f:
        cfg.write(f)


def _kill_proc(proc: subprocess.Popen) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=10,
            )
        else:
            proc.terminate()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _run_worker(server: str, workers: int, mins: int) -> int:
    log_file = _log_path()
    log_file.write_text("[worker] init...\n", encoding="utf-8")
    cfg = load_config()
    os.environ["COLLECT_PROXY_API"] = cfg.get("proxy_api", DEFAULT_PROXY)
    devnull = open(os.devnull, "w", encoding="utf-8")
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = devnull
    try:
        from live_collect_client import run_collect, set_log_path
        set_log_path(log_file)
        return run_collect(
            server=server,
            workers=workers,
            duration=max(60, mins * 60),
            proxy_api=os.environ.get("COLLECT_PROXY_API", ""),
        )
    except Exception:
        import traceback
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("\n" + traceback.format_exc())
        return 1
    finally:
        sys.stdout, sys.stderr = old_out, old_err
        devnull.close()


def _run_gui() -> None:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass

    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, ctypes.c_void_p, wintypes.HINSTANCE, wintypes.LPVOID,
    ]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.DefWindowProcW.restype = LRESULT

    def send_msg(hwnd, msg, wparam, lparam):
        return user32.SendMessageW(hwnd, msg, wparam, lparam)

    def hwnd_of(v):
        return wintypes.HWND(v or 0)

    def hinst_of(v):
        return wintypes.HINSTANCE(v)

    def hmenu_of(ctrl_id):
        return ctypes.c_void_p(ctrl_id) if ctrl_id else None

    def mkwin(ex, cls, title, style, x, y, w, h, parent, ctrl_id, inst):
        hwnd = user32.CreateWindowExW(
            wintypes.DWORD(ex), cls, title, wintypes.DWORD(style),
            x, y, w, h, hwnd_of(parent), hmenu_of(ctrl_id), hinst_of(inst), None,
        )
        if not hwnd:
            raise OSError("CreateWindowExW failed: %s" % kernel32.GetLastError())
        return hwnd

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", wintypes.UINT), ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR),
        ]

    EM_SETSEL = 0x00B1
    EM_SCROLLCARET = 0x00B7
    EM_LINESCROLL = 0x00B6
    EM_GETLINECOUNT = 0x00BA

    state = {
        "proc": None, "running": False, "hwnd_main": None, "hwnd_btn": None, "hwnd_log": None,
    }

    def get_text(hwnd):
        n = user32.GetWindowTextLengthW(hwnd) + 1
        buf = ctypes.create_unicode_buffer(n)
        user32.GetWindowTextW(hwnd, buf, n)
        return buf.value.strip()

    def set_log(text: str) -> None:
        hwnd = state["hwnd_log"]
        if not hwnd:
            return
        user32.SetWindowTextW(hwnd, (text or "").replace("\n", "\r\n"))
        send_msg(hwnd, EM_SETSEL, 0xFFFFFFFF, 0xFFFFFFFF)
        send_msg(hwnd, EM_SCROLLCARET, 0, 0)

    def clear_log() -> None:
        set_log("")
        try:
            _log_path().write_text("", encoding="utf-8")
        except Exception:
            pass

    def refresh_log() -> None:
        p = _log_path()
        if not p.is_file():
            return
        try:
            size = p.stat().st_size
            with open(p, "rb") as f:
                if size > 100000:
                    f.seek(size - 100000)
                raw = f.read()
            text = raw.decode("utf-8", errors="replace")
            if size > 100000:
                nl = text.find("\n")
                if nl >= 0:
                    text = text[nl + 1:]
            set_log(text)
        except Exception:
            pass

    def on_done(exit_code: int = 0) -> None:
        state["running"] = False
        state["proc"] = None
        user32.KillTimer(state["hwnd_main"], TIMER_ID)
        refresh_log()
        if exit_code != 0:
            try:
                with open(_log_path(), "a", encoding="utf-8") as f:
                    f.write("\n[gui] worker exited with code %s\n" % exit_code)
            except Exception:
                pass
            refresh_log()
        if state["hwnd_btn"]:
            user32.EnableWindow(state["hwnd_btn"], True)
            user32.SetWindowTextW(state["hwnd_btn"], "Start")

    def on_start() -> None:
        if state["running"]:
            return
        try:
            cfg = load_config()
            workers = int(get_text(state["hwnd_workers"]) or "1")
            minutes = int(get_text(state["hwnd_minutes"]) or "1")
        except ValueError:
            set_log("threads/minutes must be numbers")
            return
        if workers < 1 or workers > 200 or minutes < 1:
            set_log("threads 1-200, minutes >= 1")
            return
        server = get_text(state["hwnd_server"]).rstrip("/")
        if not server:
            set_log("server url required")
            return
        if not (server.startswith("http://") or server.startswith("https://")):
            set_log("server url must start with http:// or https://")
            return
        try:
            save_config({
                "server": server,
                "workers": str(workers),
                "minutes": str(minutes),
                "proxy_api": cfg.get("proxy_api", DEFAULT_PROXY),
            })
            clear_log()
            state["running"] = True
            user32.SetWindowTextW(state["hwnd_btn"], "Running")
            user32.EnableWindow(state["hwnd_btn"], False)
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            env["COLLECT_PROXY_API"] = cfg.get("proxy_api", DEFAULT_PROXY)
            state["proc"] = subprocess.Popen(
                [sys.executable, "--run", server, str(workers), str(minutes)],
                cwd=str(_exe_dir()),
                env=env,
                creationflags=0x08000000,
            )
            user32.SetTimer(state["hwnd_main"], TIMER_ID, 500, None)
        except Exception as e:
            state["running"] = False
            if state["hwnd_btn"]:
                user32.EnableWindow(state["hwnd_btn"], True)
                user32.SetWindowTextW(state["hwnd_btn"], "Start")
            set_log("[gui] start failed: %s" % e)

    def wnd_proc(hwnd, msg, wparam, lparam):
        if msg == WM_TIMER and wparam == TIMER_ID:
            refresh_log()
            proc = state["proc"]
            if proc is not None and proc.poll() is not None:
                on_done(proc.returncode or 0)
            return 0
        if msg == 0x0111 and (wparam & 0xFFFF) == ID_START:
            on_start()
            return 0
        if msg == 0x0010:
            _kill_proc(state["proc"])
            user32.KillTimer(hwnd, TIMER_ID)
            user32.DestroyWindow(hwnd)
            return 0
        if msg == 0x0002:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    gui_refs: list = []
    hi = kernel32.GetModuleHandleW(None)
    cls = "DyCollectClient_%d" % os.getpid()
    wc = WNDCLASSW()
    wc.lpfnWndProc = WNDPROC(wnd_proc)
    gui_refs.append(wc.lpfnWndProc)
    state["_gui_refs"] = gui_refs
    wc.hInstance = hi
    wc.lpszClassName = cls
    wc.hbrBackground = 6
    if not user32.RegisterClassW(ctypes.byref(wc)):
        raise OSError("RegisterClassW failed")

    child = 0x50000000
    WS_VSCROLL = 0x00200000
    ES_MULTILINE = 0x0004
    ES_AUTOVSCROLL = 0x0040
    ES_READONLY = 0x0800
    edit = child | 0x00800000
    log_style = child | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY
    static = child
    ww, wh = 580, 380
    sw, sh = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
    x, y = max(0, (sw - ww) // 2), max(0, (sh - wh) // 2)

    cfg = load_config()
    hwnd = mkwin(0, cls, "Live Collect Client", 0x00CF0000, x, y, ww, wh, None, None, hi)
    state["hwnd_main"] = hwnd
    mkwin(0, "STATIC", "Server", static, 10, 14, 46, 18, hwnd, None, hi)
    state["hwnd_server"] = mkwin(0, "EDIT", cfg["server"], edit, 58, 10, 280, 24, hwnd, ID_SERVER, hi)
    mkwin(0, "STATIC", "Threads", static, 348, 14, 50, 18, hwnd, None, hi)
    state["hwnd_workers"] = mkwin(0, "EDIT", cfg["workers"], edit, 402, 10, 44, 24, hwnd, ID_WORKERS, hi)
    mkwin(0, "STATIC", "Min", static, 454, 14, 28, 18, hwnd, None, hi)
    state["hwnd_minutes"] = mkwin(0, "EDIT", cfg["minutes"], edit, 486, 10, 36, 24, hwnd, ID_MINUTES, hi)
    state["hwnd_btn"] = mkwin(0, "BUTTON", "Start", child, 528, 9, 44, 26, hwnd, ID_START, hi)
    mkwin(0, "STATIC", "Log (proxy: client.ini)", static, 10, 42, 220, 18, hwnd, None, hi)
    state["hwnd_log"] = mkwin(0, "EDIT", "", log_style, 10, 62, 560, 300, hwnd, ID_LOG, hi)
    user32.SendMessageW(state["hwnd_log"], EM_LIMITTEXT, 512000, 0)

    user32.ShowWindow(hwnd, 5)
    user32.UpdateWindow(hwnd)

    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))


_CLIENT_MUTEX = None


def _acquire_single_instance() -> bool:
    global _CLIENT_MUTEX
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        _CLIENT_MUTEX = kernel32.CreateMutexW(None, False, "Global\\DyLiveCollectClient")
        if kernel32.GetLastError() == 183:
            return False
    except Exception:
        pass
    return True


def _warn_already_running() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            None, "CollectClient is already running.", "Live Collect Client", 0x30,
        )
    except Exception:
        pass


if __name__ == "__main__":
    if len(sys.argv) >= 5 and sys.argv[1] == "--run":
        try:
            code = _run_worker(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
        except (ValueError, IndexError):
            _log_path().write_text("invalid --run arguments\n", encoding="utf-8")
            code = 1
        raise SystemExit(code)
    if not _acquire_single_instance():
        _warn_already_running()
        raise SystemExit(0)
    if sys.platform == "win32":
        _run_gui()
    else:
        raise SystemExit("Windows only")

#!/usr/bin/env python3
"""直播间中转服务器：单 EXE，内置 MySQL，Win32 界面。"""
from __future__ import annotations

import collect_runtime
collect_runtime.init()
collect_runtime.load_env()

import os
import sys
import threading
import time
import traceback
from http.server import ThreadingHTTPServer

from live_collect_server import CollectHandler, DEFAULT_PORT
from live_collect_store import make_store

_HTTPD = None
_HTTPD_ERR = ""
_DB = None
_MUTEX = None


class _ReuseHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def _log_error(msg: str) -> None:
    try:
        log = collect_runtime._exe_dir() / "server_error.log"
        with open(log, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def _acquire_single_instance() -> bool:
    global _MUTEX
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        _MUTEX = kernel32.CreateMutexW(None, False, "Global\\DyLiveCollectServer9909")
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
            None,
            "CollectServer is already running (port %s)." % os.environ.get("COLLECT_PORT", "9909"),
            "Live Collect Server",
            0x30,
        )
    except Exception:
        pass


def _boot_http() -> None:
    global _HTTPD, _HTTPD_ERR, _DB
    try:
        port = int(os.environ.get("COLLECT_PORT", str(DEFAULT_PORT)))
        db = make_store()
        _DB = db
        CollectHandler.db = db
        CollectHandler.user_id = "admin"
        httpd = _ReuseHTTPServer(("0.0.0.0", port), CollectHandler)
        _HTTPD = httpd
        _log_error("listening on 0.0.0.0:%s backend=%s" % (
            port, os.environ.get("COLLECT_BACKEND", "mysql")))
        httpd.serve_forever()
    except Exception:
        _HTTPD_ERR = traceback.format_exc()
        _log_error(_HTTPD_ERR)


def _shutdown_http() -> None:
    global _HTTPD
    httpd = _HTTPD
    if httpd is not None:
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
        _HTTPD = None


def _read_count() -> str:
    if _HTTPD_ERR:
        return "!"
    if not _HTTPD or _DB is None:
        return "…"
    try:
        return str(_DB.stats().get("unique_rooms", 0))
    except Exception:
        return "!"


def _run_win32_gui() -> None:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    kernel32 = ctypes.windll.kernel32
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass

    port = os.environ.get("COLLECT_PORT", str(DEFAULT_PORT))
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
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.SendMessageW.restype = LRESULT

    def hwnd_of(v):
        return wintypes.HWND(v or 0)

    def hinst_of(v):
        return wintypes.HINSTANCE(v)

    def mkwin(ex, cls, title, style, x, y, w, h, parent, inst):
        hwnd = user32.CreateWindowExW(
            wintypes.DWORD(ex), cls, title, wintypes.DWORD(style),
            x, y, w, h, hwnd_of(parent), None, hinst_of(inst), None,
        )
        if not hwnd:
            raise OSError("CreateWindowExW failed: %s" % kernel32.GetLastError())
        return hwnd

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

    gui_refs: list = []
    state = {"stop": False, "hwnd_main": None, "hwnd_count": None, "hwnd_hint": None, "_gui_refs": gui_refs}
    class_name = "DyLiveCollectSrv_%d" % os.getpid()

    def wnd_proc(hwnd, msg, wparam, lparam):
        if msg == 0x0010:  # WM_CLOSE
            state["stop"] = True
            threading.Thread(target=_shutdown_http, daemon=True).start()
            user32.DestroyWindow(hwnd)
            return 0
        if msg == 0x0002:  # WM_DESTROY
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    hi = kernel32.GetModuleHandleW(None)
    wc = WNDCLASSW()
    wc.lpfnWndProc = WNDPROC(wnd_proc)
    gui_refs.append(wc.lpfnWndProc)
    wc.hInstance = hi
    wc.lpszClassName = class_name
    wc.hbrBackground = 6  # COLOR_WINDOW + 1
    if not user32.RegisterClassW(ctypes.byref(wc)):
        raise OSError("RegisterClassW failed: %s" % kernel32.GetLastError())

    child = 0x50000000  # WS_CHILD | WS_VISIBLE
    static = child
    style = 0x00CF0000  # WS_OVERLAPPEDWINDOW
    sw = user32.GetSystemMetrics(0)
    sh = user32.GetSystemMetrics(1)
    ww, wh = 280, 130
    x = max(0, (sw - ww) // 2)
    y = max(0, (sh - wh) // 2)
    title = "\u6296\u97f3\u91c7\u96c6\u670d\u52a1\u5668 :%s" % port
    if _HTTPD_ERR:
        title = "\u6296\u97f3\u91c7\u96c6\u670d\u52a1\u5668 ERR"

    hwnd = mkwin(0x00040000, class_name, title, style, x, y, ww, wh, None, hi)
    state["hwnd_main"] = hwnd
    mkwin(0, "STATIC", "Port %s" % port, static, 12, 10, 80, 20, hwnd, hi)
    mkwin(0, "STATIC", "\u552f\u4e00\u76f4\u64ad\u95f4", static, 12, 32, 120, 20, hwnd, hi)
    state["hwnd_count"] = mkwin(0, "STATIC", "\u2026", static, 12, 52, 250, 44, hwnd, hi)
    state["hwnd_hint"] = mkwin(
        0, "STATIC", "http://127.0.0.1:%s/" % port,
        static, 12, 100, 250, 20, hwnd, hi,
    )

    hfont = gdi32.CreateFontW(36, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 0, 0, "Segoe UI")
    if hfont and state["hwnd_count"]:
        user32.SendMessageW(state["hwnd_count"], 0x0030, hfont, 1)

    user32.ShowWindow(hwnd, 5)  # SW_SHOW
    user32.SetForegroundWindow(hwnd)
    user32.BringWindowToTop(hwnd)
    user32.FlashWindow(hwnd, True)
    user32.UpdateWindow(hwnd)
    _log_error("gui hwnd=%s visible" % hwnd)

    def refresh_loop() -> None:
        while not state["stop"]:
            if _HTTPD_ERR and state["hwnd_main"]:
                user32.SetWindowTextW(state["hwnd_main"], "\u6296\u97f3\u91c7\u96c6\u670d\u52a1\u5668 ERR")
            val = _read_count()
            if state["hwnd_count"]:
                user32.SetWindowTextW(state["hwnd_count"], val)
            time.sleep(3)

    threading.Thread(target=refresh_loop, daemon=True).start()

    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))


if __name__ == "__main__":
    if not _acquire_single_instance():
        _warn_already_running()
        raise SystemExit(0)
    threading.Thread(target=_boot_http, daemon=True).start()
    for _ in range(30):
        if _HTTPD or _HTTPD_ERR:
            break
        time.sleep(0.2)
    if _HTTPD_ERR and sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                None,
                "HTTP server failed to start. See server_error.log in EXE folder.",
                "Live Collect Server",
                0x10,
            )
        except Exception:
            pass
    if sys.platform == "win32":
        try:
            _run_win32_gui()
        except Exception:
            err = traceback.format_exc()
            _log_error("gui failed:\n" + err)
            try:
                import ctypes
                ctypes.windll.user32.MessageBoxW(
                    None,
                    "GUI failed (HTTP still running). See server_error.log\n\n" + err[-800:],
                    "Live Collect Server",
                    0x10,
                )
            except Exception:
                pass
            while True:
                time.sleep(3600)
    else:
        while True:
            time.sleep(3600)

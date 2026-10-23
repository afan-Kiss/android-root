# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['collect_server_app.py'],
    pathex=[],
    binaries=[],
    datas=[('bundle', 'bundle')],
    hiddenimports=['collect_runtime', 'live_collect_db', 'live_collect_mysql', 'live_collect_store', 'live_collect_server', 'live_collect_web', 'pymysql'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CollectServer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['collect_runtime', 'Cryptodome.Cipher.AES', 'live_collect_client', 'device_register']
hiddenimports += collect_submodules('Cryptodome')
hiddenimports += collect_submodules('Crypto')
hiddenimports += collect_submodules('sign')


a = Analysis(
    ['collect_client_app.py'],
    pathex=['bundle/sign_vendor', 'bundle/app'],
    binaries=[],
    datas=[('bundle', 'bundle')],
    hiddenimports=hiddenimports,
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
    name='CollectClientDbg',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

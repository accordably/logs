# -*- mode: python ; coding: utf-8 -*-
import os

import device_detector

datas = [
    (os.path.dirname(device_detector.__file__), 'device_detector')
]

block_cipher = None

a = Analysis(
    ['accordably.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'pkg_resources.py2_warn'
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='accordably',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True
)

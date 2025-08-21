# -*- mode: python ; coding: utf-8 -*-
import os
from glob import glob
from PyInstaller.utils.hooks import collect_submodules

root_dir = os.getcwd()
scripts = [os.path.join(root_dir, "gui.py"), os.path.join(root_dir, "xv2tool.py"), os.path.join(root_dir, "xv2savetool_switch.py"), os.path.join(root_dir, "xv2_ps4topc.py")]

a = Analysis(
    scripts,
    pathex=[root_dir],
    binaries=[],
    datas=[],
    hiddenimports=collect_submodules('Crypto') + collect_submodules('PyQt5'),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['README.md', '.github'],
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
    name='XV2_Save_Tool',
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
    onefile=True,
    windowed=True
)

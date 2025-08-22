# -*- mode: python ; coding: utf-8 -*-
import os
from glob import glob
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.building.build_main import Analysis, PYZ, EXE

root_dir = os.getcwd()

# Python scripts to compile
scripts = [
    os.path.join(root_dir, "gui.py"),
    os.path.join(root_dir, "xv2tool.py"),
    os.path.join(root_dir, "xv2_ps4topc.py")
]

# Include your existing .exe as a binary
binaries = [
    (os.path.join(root_dir, "xv2savdec_switch.exe"), ".")
]

# Hidden imports
hiddenimports = collect_submodules('Crypto') + collect_submodules('PyQt5')

# Analysis step
a = Analysis(
    scripts,
    pathex=[root_dir],
    binaries=binaries,
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['README.md', '.github', 'build.spec'],
    noarchive=False,
    optimize=0,
)

# Build the Python archive
pyz = PYZ(a.pure)

# Create the final EXE
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

# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for TraceLens

Build commands:
    Windows: pyinstaller tracelens.spec
    Linux:   pyinstaller tracelens.spec
"""

import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect all submodules
hiddenimports = [
    'tracelens.probe',
    'tracelens.probe.icmp',
    'tracelens.probe.tcp',
    'tracelens.probe.udp',
    'tracelens.probe.tracer',
    'tracelens.enrichment',
    'tracelens.enrichment.ip_classifier',
    'tracelens.enrichment.ptr_resolver',
    'tracelens.enrichment.asn_lookup',
    'tracelens.enrichment.geo_lookup',
    'tracelens.output',
    'tracelens.output.console',
    'tracelens.output.json_export',
    'tracelens.diagnostics',
    'tracelens.cache',
    'tracelens.models',
    # Dependencies
    'dns',
    'dns.resolver',
    'dns.rdatatype',
    'httpx',
    'httpx._transports',
    'httpx._transports.default',
    'rich',
    'rich.console',
    'rich.table',
    'rich.panel',
    'rich.progress',
    'click',
]

a = Analysis(
    ['tracelens/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'PIL',
        'scipy',
        'pytest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='tracelens',
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
    icon=None,  # Add icon path here if desired: 'assets/icon.ico'
)

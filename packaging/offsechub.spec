# PyInstaller spec for the OffsecHub desktop app.
#
#   cd frontend && npm ci && npm run build && cd ..
#   pyinstaller packaging/offsechub.spec --noconfirm
#
# Produces dist/OffsecHub/ (Linux, Windows) or dist/OffsecHub.app (macOS).
# Run it from the repository root.

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent  # noqa: F821 - provided by PyInstaller
BACKEND = ROOT / "backend"
DIST = ROOT / "frontend" / "dist"
if not (DIST / "index.html").exists():
    raise SystemExit("Build the frontend first: cd frontend && npm ci && npm run build")

datas = [
    (str(DIST), "frontend/dist"),
    (str(BACKEND / "app" / "data"), "app/data"),
    (str(BACKEND / "app" / "templates"), "app/templates"),
    (str(ROOT / "samples"), "samples"),
]
datas += collect_data_files("webview")  # pywebview's injected JS

hiddenimports = collect_submodules("app") + collect_submodules("uvicorn") + [
    "argon2._ffi", "_cffi_backend",
]
if sys.platform.startswith("linux"):
    hiddenimports += ["webview.platforms.gtk", "gi"]
elif sys.platform == "darwin":
    hiddenimports += ["webview.platforms.cocoa"]
else:
    hiddenimports += ["webview.platforms.edgechromium", "webview.platforms.winforms"]

a = Analysis(  # noqa: F821
    [str(ROOT / "packaging" / "offsechub_main.py")],
    pathex=[str(BACKEND)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "hypothesis", "IPython", "matplotlib", "numpy", "PIL"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="offsechub",
    console=sys.platform.startswith("linux"),  # a console keeps `offsechub open|import` useful on Linux
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="OffsecHub", upx=False)  # noqa: F821

if sys.platform == "darwin":
    app = BUNDLE(  # noqa: F821
        coll,
        name="OffsecHub.app",
        bundle_identifier="dev.offsechub.app",
        info_plist={"NSHighResolutionCapable": True, "LSMinimumSystemVersion": "11.0"},
    )

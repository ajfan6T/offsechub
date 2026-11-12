# PyInstaller spec for the OffsecHub desktop app.
#
#   cd frontend && npm ci && npm run build && cd ..
#   pyinstaller packaging/offsechub.spec --noconfirm
#
# Produces dist/OffsecHub/ (Windows: offsechub.exe, the windowed app, and
# offsechub-cli.exe, its console twin for terminal commands) or
# dist/OffsecHub.app (macOS). The installers wrap these: packaging/windows/
# (Inno Setup) and packaging/macos/ (disk image). Linux ships as a .deb that
# uses the system's WebKitGTK instead (packaging/linux/).
# Run it from the repository root.

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent  # noqa: F821 - provided by PyInstaller
sys.path.insert(0, str(ROOT / "packaging"))
from version import version  # noqa: E402

VERSION = version()
BACKEND = ROOT / "backend"
DIST = ROOT / "frontend" / "dist"
ICONS = ROOT / "packaging" / "icons"
if not (DIST / "index.html").exists():
    raise SystemExit("Build the frontend first: cd frontend && npm ci && npm run build")

datas = [
    (str(DIST), "frontend/dist"),
    # Whole folders: methodologies, finding templates, the DejaVu fonts for PDF
    # reports (with their licence), and every report template (.j2, report.docx).
    (str(BACKEND / "app" / "data"), "app/data"),
    (str(BACKEND / "app" / "templates"), "app/templates"),
    (str(ROOT / "samples"), "samples"),
]
datas += collect_data_files("webview")  # pywebview's injected JS
# python-docx reads its default document and parts (docx/templates/*): Document()
# without a file, and new headers, footers, styles or comments.
datas += collect_data_files("docx")

hiddenimports = (collect_submodules("app") + collect_submodules("uvicorn") + collect_submodules("argon2")
                 + ["_argon2_cffi_bindings", "_cffi_backend"])
# Reports: DOCX (python-docx, docxtpl) and PDF (ReportLab). ReportLab loads its
# settings and the metrics of the 14 standard fonts by name; it needs none of its
# own font files, since PDFs embed the DejaVu TTFs from app/data/fonts and the
# standard fonts are never embedded. lxml and Pillow (images in PDFs) are native
# extensions; pyinstaller-hooks-contrib covers their submodules and the compiled
# part of charset-normalizer.
hiddenimports += (collect_submodules("docx") + collect_submodules("docxtpl") + collect_submodules("reportlab.pdfbase")
                  + ["reportlab.rl_settings", "lxml.etree", "lxml._elementpath", "PIL.Image"])
if sys.platform.startswith("linux"):
    # gi.overrides make GLib.idle_add & co. Pythonic; without them pywebview's GTK
    # backend fails at runtime. WebKitGTK itself comes from the system.
    hiddenimports += ["webview.platforms.gtk"] + collect_submodules("gi")
elif sys.platform == "darwin":
    hiddenimports += ["webview.platforms.cocoa"]
else:
    hiddenimports += ["webview.platforms.edgechromium", "webview.platforms.winforms"]

a = Analysis(  # noqa: F821
    [str(ROOT / "packaging" / "offsechub_main.py")],
    pathex=[str(BACKEND)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "hypothesis", "IPython", "matplotlib", "numpy"],
    # python-docx opens docx/parts/../templates/*.xml (headers, footers, styles,
    # settings, comments). On macOS and Linux that path needs a real docx/parts
    # folder, so its sources are collected too; the modules still load from the archive.
    module_collection_mode={"docx": "pyz+py"},
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
WINDOWS = sys.platform == "win32"
ICON = str(ICONS / ("offsechub.ico" if WINDOWS else "offsechub.icns" if sys.platform == "darwin" else "offsechub.png"))


def executable(name: str, console: bool):
    return EXE(  # noqa: F821
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name=name,
        console=console,
        icon=ICON,
        upx=False,
    )


if WINDOWS:
    # A windowed exe has no console, so `offsechub import ...` would print
    # nothing: ship a console twin for the terminal.
    executables = [executable("offsechub", console=False), executable("offsechub-cli", console=True)]
else:
    executables = [executable("offsechub", console=sys.platform.startswith("linux"))]
coll = COLLECT(*executables, a.binaries, a.datas, name="OffsecHub", upx=False)  # noqa: F821

if sys.platform == "darwin":
    app = BUNDLE(  # noqa: F821
        coll,
        name="OffsecHub.app",
        icon=ICON,
        version=VERSION,
        bundle_identifier="dev.offsechub.app",
        info_plist={
            "CFBundleDisplayName": "OffsecHub",
            "CFBundleVersion": VERSION,
            "LSApplicationCategoryType": "public.app-category.developer-tools",
            "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
        },
    )

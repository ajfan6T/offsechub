# Third-party notices

OffsecHub's own code is under the [MIT licence](LICENSE). The installers also contain the components below, each under its own licence. The source code of the Python and JavaScript components is published on PyPI and npm under the names given.

## Python runtime and packaging

| Component | Licence |
|---|---|
| CPython (bundled in the Windows and macOS installers) | Python Software Foundation License |
| PyInstaller bootloader (Windows and macOS installers) | GPL-2.0 with the PyInstaller bootloader exception, which permits shipping it with programs under any licence |
| Inno Setup (the Windows installer program) | Inno Setup License |
| Microsoft Edge WebView2 Runtime bootstrapper (Windows installer, when present) | Microsoft software licence terms; it downloads the runtime from Microsoft |

The Linux `.deb` uses the distribution's own Python and WebKitGTK and installs the Python packages below into a private environment.

## Python packages

| Package | Licence |
|---|---|
| FastAPI, Starlette | MIT, BSD-3-Clause |
| Uvicorn, h11, click, anyio, idna | BSD-3-Clause, MIT, BSD-3-Clause, MIT, BSD-3-Clause |
| SQLAlchemy | MIT |
| Pydantic, pydantic-core, pydantic-settings, annotated-types, annotated-doc, typing-inspection | MIT |
| python-dotenv | BSD-3-Clause |
| typing_extensions | PSF-2.0 |
| Jinja2, MarkupSafe | BSD-3-Clause |
| defusedxml | PSF-2.0 |
| cryptography | Apache-2.0 or BSD-3-Clause (it includes OpenSSL, under Apache-2.0) |
| argon2-cffi, argon2-cffi-bindings | MIT (it includes the Argon2 reference implementation, CC0-1.0 or Apache-2.0) |
| cffi, pycparser | MIT-0, BSD-3-Clause |
| pywebview, bottle, proxy_tools | BSD-3-Clause, MIT, MIT |
| PyGObject (Linux, from the distribution) | LGPL-2.1-or-later |
| python-docx | MIT |
| **docxtpl** | **LGPL-2.1-only**, see below |
| lxml | BSD-3-Clause (it includes libxml2 and libxslt, under MIT) |
| ReportLab | BSD-3-Clause |
| charset-normalizer | MIT |
| Pillow | MIT-CMU (HPND); it includes libjpeg-turbo, libpng, zlib, libwebp, FreeType and others under their own permissive licences |
| OpenTelemetry API | Apache-2.0 |

### docxtpl and the LGPL

[docxtpl](https://github.com/elapouya/python-docx-template) renders Word report templates. It is under the GNU Lesser General Public License, version 2.1. OffsecHub uses it unmodified, as a separate library:

- On Linux it is installed from its published wheel, as a normal Python package.
- The Windows and macOS installers ship it as plain `.py` source files in a `docxtpl` folder inside the application, not compiled into the application archive. You may replace those files with another version, or a version you modified. On macOS, replacing them invalidates the app's code signature, so the app has to be signed again (for example ad hoc, with `codesign --force --deep --sign - OffsecHub.app`).

The licence text is at <https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html>. Its source code is on [PyPI](https://pypi.org/project/docxtpl/) and [GitHub](https://github.com/elapouya/python-docx-template).

## JavaScript (the user interface)

| Package | Licence |
|---|---|
| React, React DOM | MIT |
| React Router | MIT |
| TanStack Query | MIT |

## Fonts and data

| Component | Licence |
|---|---|
| DejaVu Sans and DejaVu Sans Mono (embedded in PDF reports) | Bitstream Vera Fonts licence, with DejaVu changes in the public domain. See `backend/app/data/fonts/LICENSE-DejaVu.txt`. |
| CVSS v4.0 scoring data and algorithm (`backend/app/services/cvss4.py`) | BSD-2-Clause, Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors. The full notice is in the file. |
| OWASP Web Security Testing Guide and OWASP API Security Top 10 (checklist names and structure) | CC BY-SA 4.0, OWASP Foundation |

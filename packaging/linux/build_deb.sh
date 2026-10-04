#!/usr/bin/env bash
# Build dist/offsechub_<version>_amd64.deb for Debian, Ubuntu, Kali and their
# derivatives.
#
#   packaging/linux/build_deb.sh            (after `npm run build` in frontend/)
#
# Why not a PyInstaller bundle: WebKitGTK starts helper processes from the
# system and they must be the exact version of the library that loads them,
# and PyGObject must match the system's GLib. So the package depends on the
# distribution's WebKitGTK and python3-gi, and only the pure-Python and wheel
# dependencies travel inside it: one set of wheels per CPython 3.11-3.14,
# installed offline into /opt/offsechub/venv when the package is configured.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"
VERSION="$("$PYTHON" packaging/version.py)"
PYVERSIONS="${PYVERSIONS:-3.11 3.12 3.13 3.14}"
MAINTAINER="${MAINTAINER:-OffsecHub <ajfan6T@users.noreply.github.com>}"
[[ -f frontend/dist/index.html ]] || { echo "Build the frontend first: cd frontend && npm ci && npm run build" >&2; exit 1; }

BUILD="$ROOT/build/deb"
STAGE="$BUILD/offsechub_${VERSION}_amd64"
OPT="$STAGE/opt/offsechub"
rm -rf "$BUILD"
mkdir -p "$OPT/backend" "$OPT/frontend" "$OPT/wheels" "$STAGE/DEBIAN" "$STAGE/usr/bin" \
  "$STAGE/usr/share/applications" "$STAGE/usr/share/icons/hicolor/scalable/apps"

# The app keeps the repository's layout, so it finds its UI and samples as in a checkout.
cp -r backend/app "$OPT/backend/app"
cp -r frontend/dist "$OPT/frontend/dist"
cp -r samples "$OPT/samples"
find "$OPT" -name __pycache__ -type d -prune -exec rm -rf {} +

"$PYTHON" - > "$OPT/requirements.txt" <<'EOF'
import tomllib
print("\n".join(tomllib.load(open("backend/pyproject.toml", "rb"))["project"]["dependencies"]))
EOF

# Pure-Python dependencies published only as source (e.g. proxy_tools) become
# wheels here; everything else is downloaded as a binary wheel per Python version.
"$PYTHON" -m pip wheel --quiet --disable-pip-version-check -r "$OPT/requirements.txt" -w "$BUILD/host-wheels"
cp "$BUILD"/host-wheels/*-none-any.whl "$OPT/wheels/"
for v in $PYVERSIONS; do
  "$PYTHON" -m pip download --quiet --disable-pip-version-check --only-binary=:all: \
    --implementation cp --python-version "$v" \
    --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 \
    --platform manylinux_2_28_x86_64 --platform manylinux_2_34_x86_64 \
    --find-links "$OPT/wheels" -d "$OPT/wheels" -r "$OPT/requirements.txt"
done

install -m 0755 /dev/stdin "$STAGE/usr/bin/offsechub" <<'EOF'
#!/bin/sh
# OffsecHub (Debian package): the app lives in /opt/offsechub.
# -I: ignore PYTHON* variables, the user's site-packages and the current directory.
exec /opt/offsechub/venv/bin/python -I -m app "$@"
EOF

cat > "$STAGE/usr/share/applications/offsechub.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=OffsecHub
GenericName=Penetration test workspace
Comment=Local-first, encrypted workspace for penetration testing engagements
Exec=offsechub
Icon=offsechub
Terminal=false
Categories=Utility;Security;
Keywords=pentest;security;scope;findings;evidence;report;
EOF
for size in 48 128 256 512; do
  install -D -m 0644 "packaging/icons/offsechub-$size.png" "$STAGE/usr/share/icons/hicolor/${size}x$size/apps/offsechub.png"
done
cp packaging/icons/offsechub.svg "$STAGE/usr/share/icons/hicolor/scalable/apps/offsechub.svg"

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
APP=/opt/offsechub
if [ "$1" = configure ]; then
  # The system Python that has PyGObject (python3-gi): its GTK and WebKit bindings
  # must come from the distribution.
  PY=
  for c in /usr/bin/python3 /usr/bin/python3.14 /usr/bin/python3.13 /usr/bin/python3.12 /usr/bin/python3.11; do
    if [ -x "$c" ] && "$c" -c 'import sys, gi; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
      PY=$c
      break
    fi
  done
  if [ -z "$PY" ]; then
    echo "offsechub: needs Python 3.11 or later with python3-gi" >&2
    exit 1
  fi
  rm -rf "$APP/venv"
  "$PY" -m venv --system-site-packages "$APP/venv"
  "$APP/venv/bin/python" -m pip install --quiet --no-index --find-links "$APP/wheels" --ignore-installed \
    --disable-pip-version-check --no-warn-script-location --no-cache-dir -r "$APP/requirements.txt"
  SITE=$("$APP/venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
  echo "$APP/backend" > "$SITE/offsechub.pth"
  "$APP/venv/bin/python" -m compileall -q "$APP/backend/app" > /dev/null || true
  if command -v update-desktop-database > /dev/null; then update-desktop-database -q /usr/share/applications || true; fi
  if command -v gtk-update-icon-cache > /dev/null; then gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true; fi
fi
exit 0
EOF

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
# Files created by postinst, which dpkg doesn't know about. Vaults and settings
# live in the user's home and are never touched.
case "$1" in
  remove|upgrade|deconfigure)
    rm -rf /opt/offsechub/venv
    find /opt/offsechub -depth -type d -name __pycache__ -exec rm -rf {} + 2> /dev/null || true
    ;;
esac
exit 0
EOF

INSTALLED_KB=$(du -sk "$STAGE" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<EOF
Package: offsechub
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Installed-Size: $INSTALLED_KB
Depends: python3 (>= 3.11), python3-venv, python3-gi, gir1.2-gtk-3.0, gir1.2-webkit2-4.1
Recommends: xdg-utils
Maintainer: $MAINTAINER
Homepage: https://github.com/ajfan6T/offsechub
Description: Local-first, encrypted workspace for penetration testers
 Scope, targets, recon imports, testing checklists, evidence, findings,
 operator logs and client-ready reports in one encrypted vault on your own
 disk. No server, no account, no network.
EOF

chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"
find "$STAGE" -path "$STAGE/DEBIAN" -prune -o -type d -exec chmod 0755 {} +
find "$STAGE/opt" "$STAGE/usr/share" -type f -exec chmod 0644 {} +
mkdir -p dist
OUT="dist/offsechub_${VERSION}_amd64.deb"
dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$OUT"
echo "Built $OUT ($(du -h "$OUT" | cut -f1))"

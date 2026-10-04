#!/usr/bin/env bash
# Build dist/OffsecHub-<version>-macOS-<arch>.dmg: drag OffsecHub.app to Applications.
#
#   packaging/macos/build_dmg.sh        (after `npm run build` in frontend/)
#
# The app is ad-hoc signed. Without an Apple Developer ID signature and
# notarization, Gatekeeper asks the user to confirm the first launch
# (System Settings > Privacy & Security > Open Anyway). Set SIGN_IDENTITY to a
# "Developer ID Application: ..." identity to sign it properly instead.
set -euo pipefail
cd "$(dirname "$0")/../.."
PYTHON="${PYTHON:-python3}"
VERSION="$("$PYTHON" packaging/version.py)"
ARCH="$(uname -m)"

"$PYTHON" -m PyInstaller packaging/offsechub.spec --noconfirm --distpath dist --workpath build/pyinstaller
APP=dist/OffsecHub.app
if [[ -n "${SIGN_IDENTITY:-}" ]]; then
  codesign --force --deep --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP"
else
  codesign --force --deep --sign - "$APP"
fi
codesign --verify --deep --strict "$APP"

STAGE=build/dmg
rm -rf "$STAGE"
mkdir -p "$STAGE"
ditto "$APP" "$STAGE/OffsecHub.app"
ln -s /Applications "$STAGE/Applications"
OUT="dist/OffsecHub-$VERSION-macOS-$ARCH.dmg"
rm -f "$OUT"
hdiutil create -volname "OffsecHub $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$OUT"
echo "Built $OUT ($(du -h "$OUT" | cut -f1))"

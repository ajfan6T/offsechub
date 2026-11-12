#!/usr/bin/env bash
# Build dist/OffsecHub-<version>-macOS-<arch>.dmg: drag OffsecHub.app to Applications.
#
#   packaging/macos/build_dmg.sh        (after `npm run build` in frontend/)
#
# <arch> is arm64 (Apple silicon) or x86_64 (Intel): the architecture of the
# Python that runs PyInstaller, which builds for its own. Every binary in the app
# is checked for that architecture and for macOS 11, the app's minimum.
#
# Signing (docs/CODE_SIGNING.md):
#   MACOS_SIGN_IDENTITY   "Developer ID Application: Name (TEAMID)" in the keychain.
#                         Unset: signed ad hoc, and Gatekeeper asks the user to
#                         confirm the first launch.
#   APPLE_API_KEY_PATH, APPLE_API_KEY_ID, APPLE_API_ISSUER_ID
#                         App Store Connect API key: notarize the app and the disk
#                         image and staple the tickets, so Gatekeeper opens them
#                         without a warning, even offline.
set -euo pipefail
cd "$(dirname "$0")/../.."
PYTHON="${PYTHON:-python3}"
VERSION="$("$PYTHON" packaging/version.py)"
ARCH="$("$PYTHON" -c 'import platform; print(platform.machine())')"  # arm64 or x86_64
MIN_MACOS=11.0  # LSMinimumSystemVersion in packaging/offsechub.spec
IDENTITY="${MACOS_SIGN_IDENTITY:--}"
NOTARIZE=0
if [[ "$IDENTITY" != "-" && -n "${APPLE_API_KEY_PATH:-}" ]]; then NOTARIZE=1; fi

json_field() {  # json_field JSON KEY: the key's value, or nothing if JSON isn't JSON
  "$PYTHON" -c 'import json, sys
try:
    print(json.loads(sys.argv[1]).get(sys.argv[2], ""))
except (ValueError, AttributeError):
    pass' "$1" "$2"
}

macos_version() {  # 10.13 -> 1013, 11.0 -> 1100
  local major minor
  IFS=. read -r major minor _ <<< "$1"
  echo $(( major * 100 + ${minor:-0} ))
}

# Every Mach-O file in the app must contain $ARCH code that runs on macOS $MIN_MACOS.
# PyInstaller checks the architecture of what it collects; this also catches a
# library compiled on this machine for its own, newer macOS.
check_app() {
  local file archs minos bad=0
  while IFS= read -r -d '' file; do
    [[ "$(file -b "$file")" == *Mach-O* ]] || continue
    archs="$(lipo -archs "$file")"
    if [[ " $archs " != *" $ARCH "* ]]; then
      echo "no $ARCH code ($archs): $file" >&2
      bad=1
      continue
    fi
    # The minimum macOS from the load commands: LC_BUILD_VERSION (minos), or
    # LC_VERSION_MIN_MACOSX (version) in older binaries.
    minos="$(otool -arch "$ARCH" -l "$file" | awk '
      $1 == "cmd" { cmd = $2 }
      !v && cmd == "LC_BUILD_VERSION" && $1 == "minos" { v = $2 }
      !v && cmd == "LC_VERSION_MIN_MACOSX" && $1 == "version" { v = $2 }
      END { print v }')"
    if [[ -n "$minos" ]] && (( $(macos_version "$minos") > $(macos_version "$MIN_MACOS") )); then
      echo "needs macOS $minos: $file" >&2
      bad=1
    fi
  done < <(find "$1/Contents" -type f -print0)
  if (( bad )); then
    echo "$1 must be $ARCH code for macOS $MIN_MACOS or later" >&2
    exit 1
  fi
  echo "$1: $ARCH code for macOS $MIN_MACOS or later"
}

notarize() {  # submit a file, wait for Apple's verdict, show the log if rejected
  local result id status
  result="$(xcrun notarytool submit "$1" --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" \
    --issuer "$APPLE_API_ISSUER_ID" --wait --timeout 1h --output-format json)" || true
  id="$(json_field "$result" id)"
  status="$(json_field "$result" status)"
  echo "notarization of $(basename "$1"): ${status:-failed} ($id)"
  if [[ "$status" != "Accepted" ]]; then
    [[ -n "$id" ]] && xcrun notarytool log "$id" --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" \
      --issuer "$APPLE_API_ISSUER_ID" || true
    exit 1
  fi
}

"$PYTHON" -m PyInstaller packaging/offsechub.spec --noconfirm --distpath dist --workpath build/pyinstaller
APP=dist/OffsecHub.app
check_app "$APP"
packaging/macos/sign_app.sh "$IDENTITY" "$APP"
if (( NOTARIZE )); then
  ditto -c -k --keepParent "$APP" build/OffsecHub-notarize.zip
  notarize build/OffsecHub-notarize.zip
  xcrun stapler staple "$APP"  # the app opens offline once copied out of the disk image
fi

STAGE=build/dmg
rm -rf "$STAGE"
mkdir -p "$STAGE"
ditto "$APP" "$STAGE/OffsecHub.app"
ln -s /Applications "$STAGE/Applications"
OUT="dist/OffsecHub-$VERSION-macOS-$ARCH.dmg"
rm -f "$OUT"
hdiutil create -volname "OffsecHub $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$OUT"
if [[ "$IDENTITY" != "-" ]]; then
  codesign --force --timestamp --sign "$IDENTITY" "$OUT"
fi
if (( NOTARIZE )); then
  notarize "$OUT"
  xcrun stapler staple "$OUT"
  spctl --assess --type open --context context:primary-signature --verbose "$OUT"
  spctl --assess --type execute --verbose "$APP"
fi
echo "Built $OUT ($(du -h "$OUT" | cut -f1)), $([[ "$IDENTITY" == "-" ]] && echo "ad-hoc signed" || echo "signed by $IDENTITY")$( (( NOTARIZE )) && echo ", notarized")"

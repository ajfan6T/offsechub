#!/usr/bin/env bash
# Sign OffsecHub.app inside out, with the hardened runtime notarization requires.
#
#   packaging/macos/sign_app.sh "Developer ID Application: Name (TEAMID)" dist/OffsecHub.app
#   packaging/macos/sign_app.sh - dist/OffsecHub.app        ad hoc (unsigned builds, CI)
#
# Every Mach-O file in the bundle is signed first, then the app with its entitlements.
set -euo pipefail
IDENTITY="$1"
APP="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
ENTITLEMENTS="$HERE/entitlements.plist"
TIMESTAMP=(--timestamp)
if [[ "$IDENTITY" == "-" ]]; then
  # An ad-hoc signature has no Team ID, so library validation ("same team only")
  # can never pass; allow it for ad-hoc builds only. Developer ID builds keep it.
  ENTITLEMENTS="$(mktemp -d)/entitlements.plist"
  cp "$HERE/entitlements.plist" "$ENTITLEMENTS"
  /usr/libexec/PlistBuddy -c "Add :com.apple.security.cs.disable-library-validation bool true" "$ENTITLEMENTS"
  TIMESTAMP=(--timestamp=none)
fi
sign() { codesign --force --options runtime "${TIMESTAMP[@]}" --sign "$IDENTITY" "$@"; }

MAIN="$APP/Contents/MacOS/offsechub"
count=0
while IFS= read -r -d '' file; do
  if [[ "$file" != "$MAIN" ]] && file -b "$file" | grep -q "Mach-O"; then
    sign "$file"
    count=$((count + 1))
  fi
done < <(find "$APP/Contents" -type f -print0)
sign --entitlements "$ENTITLEMENTS" "$APP"
codesign --verify --deep --strict "$APP"
echo "Signed $APP and $count nested binaries as ${IDENTITY/#-/ad hoc}"

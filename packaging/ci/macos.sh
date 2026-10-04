#!/usr/bin/env bash
# CI: build the disk image, install the app from it, check its signature,
# smoke-test the installed app. Signs and notarizes when MACOS_SIGN_IDENTITY
# and the notarization key are set (packaging/macos/build_dmg.sh); otherwise
# the app is signed ad hoc, still with the hardened runtime, so every build
# proves the app runs under it.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ -z "${MACOS_SIGN_IDENTITY:-}" ]]; then
  echo "::warning::No Developer ID configured: building an ad-hoc signed disk image"
fi
python -m pip install -e "./backend[build]"
packaging/macos/build_dmg.sh

TMP="${RUNNER_TEMP:-$(mktemp -d)}"
hdiutil attach dist/OffsecHub-*.dmg -nobrowse -mountpoint "$TMP/dmg"
ditto "$TMP/dmg/OffsecHub.app" "$TMP/Applications/OffsecHub.app"
hdiutil detach "$TMP/dmg"
APP="$TMP/Applications/OffsecHub.app"
codesign --verify --deep --strict "$APP"
details="$(codesign --display --verbose=2 "$APP" 2>&1)"
echo "$details" | grep -E "^(Authority|TeamIdentifier|Runtime Version|flags)|flags=" || true
# e.g. "flags=0x10002(adhoc,runtime)" or "flags=0x10000(runtime)"
grep -Eq 'flags=0x[0-9a-f]+\([^)]*runtime' <<< "$details" || { echo "the app is not signed with the hardened runtime" >&2; exit 1; }
python packaging/smoke_test.py --app "$APP/Contents/MacOS/offsechub"

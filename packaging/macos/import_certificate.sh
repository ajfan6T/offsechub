#!/usr/bin/env bash
# CI: put the Developer ID certificate and the notarization key where the build finds them.
#
# Reads MACOS_CERTIFICATE (base64 of the .p12 export), MACOS_CERTIFICATE_PASSWORD
# and APPLE_API_KEY (the App Store Connect .p8 key, as text). Writes
# MACOS_SIGN_IDENTITY and APPLE_API_KEY_PATH to $GITHUB_ENV for later steps.
set -euo pipefail
: "${MACOS_CERTIFICATE:?}" "${MACOS_CERTIFICATE_PASSWORD:?}" "${APPLE_API_KEY:?}"
KEYCHAIN="$RUNNER_TEMP/signing.keychain-db"
KEYCHAIN_PASSWORD="$(uuidgen)"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
umask 077
echo "$MACOS_CERTIFICATE" | base64 --decode > "$RUNNER_TEMP/certificate.p12"
security import "$RUNNER_TEMP/certificate.p12" -k "$KEYCHAIN" -P "$MACOS_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
rm -f "$RUNNER_TEMP/certificate.p12"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" > /dev/null
# shellcheck disable=SC2046
security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')

IDENTITY="$(security find-identity -v -p codesigning "$KEYCHAIN" | sed -n 's/.*"\(Developer ID Application: .*\)"$/\1/p' | head -1)"
if [[ -z "$IDENTITY" ]]; then
  echo "No 'Developer ID Application' identity in MACOS_CERTIFICATE" >&2
  exit 1
fi
printf '%s\n' "$APPLE_API_KEY" > "$RUNNER_TEMP/AuthKey.p8"
{
  echo "MACOS_SIGN_IDENTITY=$IDENTITY"
  echo "APPLE_API_KEY_PATH=$RUNNER_TEMP/AuthKey.p8"
} >> "$GITHUB_ENV"
echo "Signing as: $IDENTITY"

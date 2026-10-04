#!/usr/bin/env bash
# Build the installer for this OS into dist/:
#   Linux  offsechub_<version>_amd64.deb         (packaging/linux/build_deb.sh)
#   macOS  OffsecHub-<version>-macOS-<arch>.dmg  (packaging/macos/build_dmg.sh)
# On Windows, run packaging\build.ps1 instead.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"

(cd frontend && npm ci && npm run build)
case "$(uname)" in
  Linux)
    packaging/linux/build_deb.sh
    ;;
  Darwin)
    "$PYTHON" -m pip install -e "./backend[build]"
    packaging/macos/build_dmg.sh
    ;;
  *)
    echo "Unsupported OS: $(uname). On Windows use packaging\\build.ps1." >&2
    exit 1
    ;;
esac

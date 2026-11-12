#!/usr/bin/env bash
# Build the installer for this OS into dist/:
#   Linux  offsechub_<version>_<arch>.deb        (packaging/linux/build_deb.sh)
#   macOS  OffsecHub-<version>-macOS-<arch>.dmg  (packaging/macos/build_dmg.sh)
# for this machine's architecture: amd64/x86_64 or arm64.
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
    # --prefer-binary: see packaging/ci/macos.sh.
    "$PYTHON" -m pip install --prefer-binary -e "./backend[build]"
    packaging/macos/build_dmg.sh
    ;;
  *)
    echo "Unsupported OS: $(uname). On Windows use packaging\\build.ps1." >&2
    exit 1
    ;;
esac

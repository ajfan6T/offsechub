#!/usr/bin/env bash
# Build the desktop app for the current OS (Linux or macOS) into dist/.
set -euo pipefail
cd "$(dirname "$0")/.."

(cd frontend && npm ci && npm run build)
python -m pip install -e "./backend[build]"
if [[ "$(uname)" == "Linux" ]]; then python -m pip install -e "./backend[gtk]"; fi
pyinstaller packaging/offsechub.spec --noconfirm --distpath dist --workpath build/pyinstaller

echo "Built: $(ls -d dist/OffsecHub* | tr '\n' ' ')"

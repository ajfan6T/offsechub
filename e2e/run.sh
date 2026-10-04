#!/usr/bin/env bash
# End-to-end runs of the real app, from a throwaway config and vault folder.
#
#   e2e/run.sh            browser mode (Playwright + Chromium), then the native window
#   e2e/run.sh browser    only the browser run
#   e2e/run.sh native     only the native window (WebKitGTK; uses xvfb-run if there is no display)
#
# Needs: the backend installed (pip install -e "backend[dev]"), a built frontend,
# Node with the `playwright` package (NODE_PATH or npm i -g playwright) and its
# Chromium. Screenshots land in $SHOTS (default: a temp dir, printed at the end).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-$(command -v python)}"
WHAT="${1:-all}"

export E2E_DIR="$(mktemp -d "${TMPDIR:-/tmp}/offsechub-e2e.XXXXXX")"
export SHOTS="${SHOTS:-$E2E_DIR/shots}"
export VAULTS="${VAULTS:-$E2E_DIR/OffsecHub}"
export OFFSECHUB_CONFIG_DIR="$E2E_DIR/config"
export XDG_RUNTIME_DIR="$E2E_DIR/run"
export PYTHON
mkdir -p "$SHOTS" "$VAULTS"
mkdir -m 700 "$XDG_RUNTIME_DIR"

cd "$ROOT/backend"
echo "demo-password-1234" | "$PYTHON" -m app demo "$VAULTS/Demo" --password-stdin > /dev/null
status=0

if [[ "$WHAT" == all || "$WHAT" == browser ]]; then
  "$PYTHON" -m app --browser --no-open > "$E2E_DIR/app.log" 2>&1 &
  app=$!
  for _ in $(seq 1 100); do grep -q "_launch" "$E2E_DIR/app.log" && break; sleep 0.1; done
  export LAUNCH_URL="$(grep -o 'http://127.0.0.1:[0-9]*/_launch?token=[A-Za-z0-9_-]*' "$E2E_DIR/app.log" | head -1)"
  node "$ROOT/e2e/browser.cjs" || status=1
  kill -TERM "$app"
  wait "$app" || status=1
  if [[ -e "$XDG_RUNTIME_DIR/offsechub/runtime.json" ]]; then
    echo "FAIL runtime.json left behind"
    status=1
  fi
fi

if [[ "$WHAT" == all || "$WHAT" == native ]]; then
  run=("$PYTHON" "$ROOT/e2e/native.py")
  if [[ -z "${DISPLAY:-}" ]]; then run=(xvfb-run -a -s "-screen 0 1400x900x24" "${run[@]}"); fi
  "${run[@]}" > "$E2E_DIR/native.log" 2>&1 || true
  if "$PYTHON" -c "import json,sys; r=json.load(open(sys.argv[1])); print(json.dumps(r, indent=2)); sys.exit(0 if r.get('ok') else 1)" \
      "$E2E_DIR/native-results.json"; then
    echo "PASS native window scenario"
  else
    echo "FAIL native window scenario (log: $E2E_DIR/native.log)"
    status=1
  fi
fi

echo "screenshots: $SHOTS"
exit $status

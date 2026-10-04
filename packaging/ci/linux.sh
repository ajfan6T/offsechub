#!/usr/bin/env bash
# CI: build the .deb, install it with apt as a user would, smoke-test the
# installed app (window under Xvfb, then browser mode), uninstall.
set -euo pipefail
cd "$(dirname "$0")/../.."
packaging/linux/build_deb.sh
sudo apt-get update
sudo apt-get install -y xvfb ./dist/offsechub_*_amd64.deb
xvfb-run -a python packaging/smoke_test.py --app /usr/bin/offsechub
python packaging/smoke_test.py --app /usr/bin/offsechub --browser
sudo apt-get remove -y offsechub
test ! -e /opt/offsechub

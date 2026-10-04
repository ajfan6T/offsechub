"""Print OffsecHub's version (from backend/app/__init__.py) without importing the app."""

import re
from pathlib import Path

INIT = Path(__file__).resolve().parents[1] / "backend" / "app" / "__init__.py"


def version() -> str:
    match = re.search(r'^__version__ = "([0-9]+\.[0-9]+\.[0-9]+)"$', INIT.read_text(), re.M)
    if not match:
        raise SystemExit(f"no x.y.z __version__ in {INIT}")
    return match[1]


if __name__ == "__main__":
    print(version())

"""Built-in testing methodologies (checklists) shipped as JSON files."""

import json
from functools import lru_cache
from pathlib import Path

METHODOLOGY_DIR = Path(__file__).resolve().parent.parent / "data" / "methodologies"


@lru_cache
def load_methodologies() -> dict[str, dict]:
    out = {}
    for path in sorted(METHODOLOGY_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        out[data["id"]] = data
    return out

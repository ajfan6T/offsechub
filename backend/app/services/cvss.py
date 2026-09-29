"""CVSS v3.1 base score calculator (FIRST specification, section 7)."""

import math
from dataclasses import dataclass

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": None, "C": None},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required weights differ when scope is changed.
PR_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
# Temporal/environmental metrics are accepted in vectors but do not affect the base score.
OPTIONAL_METRICS = {
    "E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
}


class CvssError(ValueError):
    pass


@dataclass
class CvssResult:
    vector: str
    score: float
    severity: str
    metrics: dict[str, str]


def roundup(value: float) -> float:
    """Round up to one decimal, avoiding floating point artefacts (spec Appendix A)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_for_score(score: float) -> str:
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.1", "CVSS:3.0"):
        raise CvssError("vector must start with CVSS:3.1/ (or CVSS:3.0/)")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, val = part.partition(":")
        if not sep:
            raise CvssError(f"malformed metric {part!r}")
        if key in metrics:
            raise CvssError(f"duplicate metric {key}")
        if key in WEIGHTS:
            if val not in WEIGHTS[key]:
                raise CvssError(f"invalid value {val!r} for {key}")
        elif key not in OPTIONAL_METRICS:
            raise CvssError(f"unknown metric {key}")
        metrics[key] = val
    missing = [m for m in BASE_METRICS if m not in metrics]
    if missing:
        raise CvssError(f"missing base metrics: {', '.join(missing)}")
    return metrics


def calculate(vector: str) -> CvssResult:
    m = parse_vector(vector)
    changed = m["S"] == "C"
    pr = (PR_SCOPE_CHANGED if changed else WEIGHTS["PR"])[m["PR"]]

    iss = 1 - (1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]] * pr * WEIGHTS["UI"][m["UI"]]

    if impact <= 0:
        score = 0.0
    elif changed:
        score = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = roundup(min(impact + exploitability, 10))

    prefix = vector.strip().split("/", 1)[0]
    canonical = prefix + "/" + "/".join(f"{k}:{m[k]}" for k in BASE_METRICS)
    extras = [f"{k}:{v}" for k, v in m.items() if k not in BASE_METRICS]
    if extras:
        canonical += "/" + "/".join(extras)
    return CvssResult(canonical, score, severity_for_score(score), m)

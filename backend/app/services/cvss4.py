"""CVSS v4.0 score calculator (FIRST CVSS v4.0 specification, "CVSS v4.0 Scoring").

CVSS v4.0 has no closed-form equation. A vector is reduced to a "macrovector" of
six equivalence classes (EQ1-EQ6) whose score was fixed by expert ranking (the
lookup table below); the vector's score is that value lowered by its mean
proportional severity distance from the highest-severity vectors of the same
macrovector. This module is a port of the reference implementation, the FIRST
calculator (https://github.com/FIRSTdotorg/cvss-v4-calculator, cvss_score.js) as
maintained by Red Hat Product Security
(https://github.com/RedHatProductSecurity/cvss-v4-calculator, cvss40.js), whose
final rounding (half up after adding 1e-6 against float artefacts) it follows.

All four nomenclatures are scored the same way: CVSS-B (base), CVSS-BT (+ threat:
E), CVSS-BE (+ environmental: CR IR AR and the M* metrics) and CVSS-BTE. Missing
or Not Defined (X) metrics take the reference defaults: E:X counts as E:A
(Attacked), CR/IR/AR:X as High, and a modified metric left at X falls back to
its base metric. Supplemental metrics (S AU R V RE U) are validated and kept in
the vector but never change the score.

The lookup table, the highest-severity vectors, the maximal severity depths and
the scoring algorithm are taken from the reference implementation:

    Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import itertools
import math

from .cvss import CvssError, CvssResult, severity_for_score

PREFIX = "CVSS:4.0"

# Every metric with its allowed values, in the specification's vector-string order:
# base, threat, environmental, supplemental.
METRICS: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
    "E": ("X", "A", "P", "U"),
    "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"),
    "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"),
    "MVI": ("X", "H", "L", "N"),
    "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"),
    "MSI": ("X", "S", "H", "L", "N"),
    "MSA": ("X", "S", "H", "L", "N"),
    "S": ("X", "N", "P"),
    "AU": ("X", "N", "Y"),
    "R": ("X", "A", "U", "I"),
    "V": ("X", "D", "C"),
    "RE": ("X", "L", "M", "H"),
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")

# Score of the highest-severity vector of each macrovector (EQ1..EQ6 digits).
LOOKUP: dict[str, float] = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
    "000100": 10.0, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0, "000220": 8.1, "000221": 6.8,
    "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8.0, "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5.0,
    "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9.0,
    "010111": 8.3, "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3, "011010": 9.2,
    "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
    "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4, "011201": 7.0, "011210": 7.1,
    "011211": 5.2, "011220": 5.0, "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
    "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
    "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
    "102001": 8.3, "102011": 7.0, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5, "110001": 9.0, "110010": 8.8,
    "110011": 7.6, "110020": 7.6, "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
    "110211": 5.9, "110220": 5.2, "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4, "111101": 5.9, "111110": 5.7,
    "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3.0,
    "112101": 5.8, "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
    "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0, "200220": 4.0, "200221": 2.2,
    "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7, "202111": 2.1, "202121": 1.1,
    "202201": 2.4, "202211": 0.9, "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3, "210101": 5.5, "210110": 5.9,
    "210111": 4.0, "210120": 4.1, "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8,
    "211011": 4.5, "211020": 4.0, "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6, "211201": 1.8, "211210": 1.7,
    "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0, "212211": 0.3, "212221": 0.1,
}

# Highest-severity vectors of each EQ level (EQ3 and EQ6 are joint: [eq3][eq6]).
MAX_COMPOSED = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        0: ["AC:L/AT:N/"],
        1: ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq3": {
        0: {
            0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        1: {
            0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            1: ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"],
        },
        2: {
            1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
        },
    },
    "eq4": {
        0: ["SC:H/SI:S/SA:S/"],
        1: ["SC:H/SI:H/SA:H/"],
        2: ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        0: ["E:A/"],
        1: ["E:P/"],
        2: ["E:U/"],
    },
}

# Maximal severity depth of each EQ level, in steps of 0.1 (+1).
MAX_SEVERITY = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
}

# Severity level of each metric value, used for distances to a highest-severity vector.
LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "E": {"U": 0.2, "P": 0.1, "A": 0.0},
}

# Not Defined threat/requirement metrics assume the worst case.
WORST_CASE = {"E": "A", "CR": "H", "IR": "H", "AR": "H"}
STEP = 0.1
EPSILON = 1e-6


def parse_vector(vector: str) -> dict[str, str]:
    """Validate a CVSS:4.0 vector; return its metrics in specification order."""
    parts = vector.strip().split("/")
    if parts[0] != PREFIX:
        raise CvssError("vector must start with CVSS:4.0/")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, val = part.partition(":")
        if not sep:
            raise CvssError(f"malformed metric {part!r}")
        if key in metrics:
            raise CvssError(f"duplicate metric {key}")
        if key not in METRICS:
            raise CvssError(f"unknown metric {key}")
        if val not in METRICS[key]:
            raise CvssError(f"invalid value {val!r} for {key}")
        metrics[key] = val
    missing = [m for m in BASE_METRICS if m not in metrics]
    if missing:
        raise CvssError(f"missing base metrics: {', '.join(missing)}")
    return {k: metrics[k] for k in METRICS if k in metrics}


def effective(m: dict[str, str], metric: str) -> str:
    """Value a metric scores with: worst-case defaults, then any modified (M*) override."""
    value = m.get(metric, "X")
    if value == "X" and metric in WORST_CASE:
        return WORST_CASE[metric]
    modified = m.get("M" + metric, "X")
    if modified != "X":
        return modified
    return value


def macrovector(m: dict[str, str]) -> str:
    """The six equivalence classes EQ1..EQ6 of a vector, e.g. "002201"."""
    av, pr, ui = effective(m, "AV"), effective(m, "PR"), effective(m, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2

    eq2 = 0 if effective(m, "AC") == "L" and effective(m, "AT") == "N" else 1

    vc, vi, va = effective(m, "VC"), effective(m, "VI"), effective(m, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2

    if effective(m, "MSI") == "S" or effective(m, "MSA") == "S":
        eq4 = 0
    elif "H" in (effective(m, "SC"), effective(m, "SI"), effective(m, "SA")):
        eq4 = 1
    else:
        eq4 = 2

    eq5 = {"A": 0, "P": 1, "U": 2}[effective(m, "E")]

    if ((effective(m, "CR") == "H" and vc == "H") or (effective(m, "IR") == "H" and vi == "H")
            or (effective(m, "AR") == "H" and va == "H")):
        eq6 = 0
    else:
        eq6 = 1

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _lookup(*eqs: int) -> float | None:
    """Score of a macrovector, or None when it does not exist (no lower macrovector)."""
    return LOOKUP.get("".join(str(e) for e in eqs))


def _round(value: float) -> float:
    """Round half up to one decimal, after nudging float artefacts like 1.4499999999999993."""
    shifted = (value + EPSILON) * 10
    whole = math.floor(shifted)
    if shifted - whole >= 0.5:
        whole += 1
    return whole / 10


def score(m: dict[str, str]) -> float:
    """CVSS v4.0 score of parsed metrics (reference algorithm, step by step)."""
    if all(effective(m, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro = macrovector(m)
    value = LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in macro)

    # 1a. Maximal scoring difference: the drop to the next lower macrovector of each EQ.
    lower_eq1 = _lookup(eq1 + 1, eq2, eq3, eq4, eq5, eq6)
    lower_eq2 = _lookup(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    if eq3 == 0 and eq6 == 0:
        # 00 -> 01 or 10: take the higher of the two.
        left = _lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
        right = _lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        lower_eq3eq6 = None if left is None or right is None else max(left, right)
    elif eq3 == 1 and eq6 == 0:
        lower_eq3eq6 = _lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1)  # 10 -> 11
    elif eq6 == 1 and eq3 in (0, 1):
        lower_eq3eq6 = _lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6)  # 01 -> 11, 11 -> 21
    else:
        lower_eq3eq6 = _lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)  # 21 -> 32: none
    lower_eq4 = _lookup(eq1, eq2, eq3, eq4 + 1, eq5, eq6)
    lower_eq5 = _lookup(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    # 1b. Severity distance from the first highest-severity vector of this macrovector
    # that the scored vector does not exceed in any metric.
    max_vectors = itertools.product(
        MAX_COMPOSED["eq1"][eq1],
        MAX_COMPOSED["eq2"][eq2],
        MAX_COMPOSED["eq3"][eq3][eq6],
        MAX_COMPOSED["eq4"][eq4],
        MAX_COMPOSED["eq5"][eq5],
    )
    current = {k: LEVELS[k][effective(m, k)] for k in LEVELS}
    distances: dict[str, float] = {}
    for parts in max_vectors:
        top = dict(p.split(":") for p in "".join(parts).rstrip("/").split("/"))
        distances = {k: current[k] - LEVELS[k][top[k]] for k in LEVELS}
        if all(d >= 0 for d in distances.values()):
            break

    distance_eq1 = distances["AV"] + distances["PR"] + distances["UI"]
    distance_eq2 = distances["AC"] + distances["AT"]
    distance_eq3eq6 = (distances["VC"] + distances["VI"] + distances["VA"]
                       + distances["CR"] + distances["IR"] + distances["AR"])
    distance_eq4 = distances["SC"] + distances["SI"] + distances["SA"]

    # 1c/1d. Proportion of the EQ's depth, times its maximal scoring difference; EQ5
    # always contributes 0 but still counts towards the mean when a lower level exists.
    steps = [
        (lower_eq1, distance_eq1, MAX_SEVERITY["eq1"][eq1] * STEP),
        (lower_eq2, distance_eq2, MAX_SEVERITY["eq2"][eq2] * STEP),
        (lower_eq3eq6, distance_eq3eq6, MAX_SEVERITY["eq3eq6"][eq3][eq6] * STEP),
        (lower_eq4, distance_eq4, MAX_SEVERITY["eq4"][eq4] * STEP),
        (lower_eq5, 0.0, 1.0),
    ]
    existing = 0
    total = 0.0
    for lower, distance, depth in steps:
        if lower is None:
            continue
        existing += 1
        total += (value - lower) * (distance / depth)

    # 2/3. Lower the macrovector's score by the mean proportional distance.
    mean_distance = total / existing if existing else 0.0
    return _round(max(0.0, min(10.0, value - mean_distance)))


def canonical(m: dict[str, str]) -> str:
    """Vector string in specification order, without Not Defined (X) metrics."""
    return "/".join([PREFIX] + [f"{k}:{m[k]}" for k in METRICS if m.get(k, "X") != "X"])


def calculate(vector: str) -> CvssResult:
    m = parse_vector(vector)
    value = score(m)
    kept = {k: v for k, v in m.items() if v != "X"}
    return CvssResult(canonical(m), value, severity_for_score(value), kept)

"""CVSS v4.0 scoring.

Expected scores were produced by Red Hat's `cvss` library (an independent implementation of the
FIRST reference calculator) while cross-checking app.services.cvss4 against it on 629,904 vectors
with no difference; this table pins a spread of them, so the library is not needed here.
"""

import pytest

from app.services import cvss, cvss4

SCORES = [
    # Base (CVSS-B). The first is the specification's own example.
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1),
    ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1),
    ("CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7),
    ("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.0),
    ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 1.0),
    ("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:L", 1.0),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H", 8.9),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 5.3),
    # 8.549999999999999 before rounding: must round half up to 8.6, not down to 8.5.
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H", 8.6),
    ("CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 1.0),
    # Threat (CVSS-BT)
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", 8.9),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 8.1),
    ("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:U", 0.1),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:N/E:P", 7.3),
    # Environmental (CVSS-BE)
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/MAV:A", 8.7),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:L", 8.9),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M/AR:M", 9.0),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:H/AR:H", 6.9),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MSI:S", 10.0),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/MSA:S", 7.8),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N", 0.0),
    ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
     "/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H", 9.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:L/IR:H/AR:M/MVI:H", 9.3),
    ("CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:H/VA:N/SC:H/SI:L/SA:N/CR:M/IR:L/AR:H/MPR:H/MSC:L", 1.7),
    # Threat + environmental, with supplemental metrics (CVSS-BTE)
    ("CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/MAV:A/AU:N/R:A", 7.7),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:L/IR:L/AR:L", 7.9),
    ("CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P/CR:H/IR:M/AR:L/MAC:L/MSI:S"
     "/S:P/AU:Y/R:I/V:C/RE:H/U:Red", 9.2),
    ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:L/SC:N/SI:H/SA:N/E:P/AR:H/MUI:N/MVA:H/S:N/U:Amber", 7.1),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/R:U/V:D/RE:L/U:Clear", 9.3),
]

BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


@pytest.mark.parametrize("vector,score", SCORES)
def test_cvss4_scores(vector, score):
    r = cvss.calculate(vector)
    assert r.score == score
    assert r.vector == vector  # already canonical


@pytest.mark.parametrize("score,severity", [
    (0.0, "info"), (0.1, "low"), (5.1, "medium"), (6.9, "medium"),
    (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
])
def test_cvss4_uses_the_shared_severity_scale(score, severity):
    vector = next(v for v, s in SCORES if s == score)
    assert cvss.calculate(vector).severity == severity


def test_spec_example_through_both_entry_points():
    for r in (cvss.calculate(BASE), cvss4.calculate(BASE)):
        assert (r.vector, r.score, r.severity) == (BASE, 9.3, "critical")
        assert r.metrics["AT"] == "N" and len(r.metrics) == 11


def test_not_defined_threat_and_requirements_assume_the_worst():
    # E:X counts as E:A (Attacked); CR/IR/AR:X count as High.
    assert cvss.calculate(BASE + "/E:X").score == cvss.calculate(BASE + "/E:A").score == 9.3
    assert cvss.calculate(BASE + "/CR:X/IR:X/AR:X").score == cvss.calculate(BASE + "/CR:H/IR:H/AR:H").score
    assert cvss.calculate(BASE + "/CR:L/IR:L/AR:L").score < 9.3


def test_modified_metrics_override_base_and_x_falls_back():
    physical = "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert cvss.calculate(physical).score == 7.0
    assert cvss.calculate(physical + "/MAV:N").score == cvss.calculate(BASE).score
    assert cvss.calculate(physical + "/MAV:X").score == 7.0
    # A modified subsequent-system Safety impact (S) lifts EQ4 to its top level.
    assert cvss.calculate(BASE + "/MSI:S").score == 10.0


def test_supplemental_metrics_never_change_the_score():
    supplemental = "/S:P/AU:Y/R:I/V:C/RE:H/U:Red"
    checked = 0
    for vector, score in SCORES:
        if not set(cvss4.parse_vector(vector)) & {"S", "AU", "R", "V", "RE", "U"}:
            assert cvss.calculate(vector + supplemental).score == score
            checked += 1
    assert checked > 25


def test_canonical_order_drops_not_defined_and_keeps_extras():
    shuffled = ("CVSS:4.0/U:Green/SA:N/E:P/AV:N/MAV:L/VI:H/CR:X/AC:L/SI:N/R:A/AT:N/VA:H/PR:N/SC:N/UI:N"
                "/VC:H/AR:M/S:X")
    r = cvss.calculate(f"  {shuffled}  ")
    assert r.vector == ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                        "/E:P/AR:M/MAV:L/R:A/U:Green")
    assert list(r.metrics) == ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
                               "E", "AR", "MAV", "R", "U"]
    assert r.score == cvss.calculate(r.vector).score == 7.2


def test_full_vector_is_longer_than_the_old_column_size():
    full = ("CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:L/SI:H/SA:N/E:P/CR:M/IR:H/AR:L"
            "/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:L/MSC:H/MSI:S/MSA:H"
            "/S:P/AU:Y/R:U/V:C/RE:M/U:Amber")
    r = cvss.calculate(full)
    assert r.vector == full and len(full) > 128 and len(r.metrics) == 32
    assert r.score == 9.7


@pytest.mark.parametrize("vector,message", [
    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "must start with"),
    ("CVSS:4.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "must start with"),
    ("cvss:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "must start with"),
    ("CVSS:4.0", "missing base metrics: AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA"),
    ("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "missing base metrics: AT"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "missing base metrics: SC, SI, SA"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/E:P", "duplicate metric E"),
    ("CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "duplicate metric AV"),
    ("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "invalid value 'X' for AV"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "invalid value 'R' for UI"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N", "invalid value 'S' for SI"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MSC:S", "invalid value 'S' for MSC"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:red", "invalid value 'red' for U"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:U", "invalid value 'U' for S"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/RL:O", "unknown metric RL"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/C:H/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "unknown metric C"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/", "malformed metric ''"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VCH/VI:H/VA:H/SC:N/SI:N/SA:N", "malformed metric 'VCH'"),
])
def test_cvss4_rejects_invalid(vector, message):
    with pytest.raises(cvss.CvssError) as exc:
        cvss.calculate(vector)
    assert message in str(exc.value)


def test_version_of():
    assert cvss.version_of(BASE) == "4.0"
    assert cvss.version_of(" CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "3.1"
    assert cvss.version_of("CVSS:3.0/AV:N") == "3.0"
    assert cvss.version_of("CVSS:4.0") == "4.0"
    assert cvss.version_of("CVSS:2.0/AV:N") == "" and cvss.version_of("") == ""


def test_cvss3_still_scored_and_rejected_as_before():
    assert cvss.calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").score == 9.8
    with pytest.raises(cvss.CvssError, match="CVSS:4.0/"):
        cvss.calculate("junk")
    # A 3.1 vector labelled 4.0 is not silently accepted.
    with pytest.raises(cvss.CvssError):
        cvss.calculate("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_cvss4_endpoint(api):
    reversed_order = "CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N"
    r = api.ok("POST", "/api/cvss", status=200, json={"vector": reversed_order})
    assert (r["vector"], r["score"], r["severity"]) == (BASE, 9.3, "critical")
    bad = api.post("/api/cvss", json={"vector": "CVSS:4.0/AV:N"})
    assert bad.status_code == 422 and "missing base metrics" in bad.text


def test_finding_and_template_store_cvss4_vectors(api, engagement):
    full = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:N/E:P/CR:H/IR:M/AR:L"
            "/MAV:A/MAC:H/MAT:P/MPR:H/MUI:A/MVC:L/MVI:L/MVA:L/MSC:H/MSI:S/MSA:N/S:P/AU:Y/R:I/V:C/RE:H/U:Red")
    base = f"/api/engagements/{engagement['id']}/findings"
    f = api.ok("POST", base, json={"title": "Auth bypass", "cvss_vector": full})
    assert (f["cvss_vector"], f["cvss_score"], f["severity"]) == (full, 2.1, "low")
    f = api.ok("PATCH", f"{base}/{f['id']}", json={"cvss_vector": BASE})
    assert (f["cvss_score"], f["severity"]) == (9.3, "critical")
    assert api.patch(f"{base}/{f['id']}", json={"cvss_vector": BASE + "/E:Q"}).status_code == 422

    tpl = api.ok("POST", "/api/finding-templates", json={"title": "CVSS 4 template", "cvss_vector": full})
    assert tpl["cvss_vector"] == full and tpl["cvss_score"] == 2.1


def test_reports_label_each_vector_with_its_version(api, engagement):
    base = f"/api/engagements/{engagement['id']}"
    v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    for title, vector in [("Old school", v31), ("New school", BASE)]:
        api.ok("POST", f"{base}/findings", json={"title": title, "status": "confirmed", "cvss_vector": vector})
    html = api.get(f"{base}/report").text
    assert "<dt>CVSS v3.1</dt>" in html and "<dt>CVSS v4.0</dt>" in html
    md = api.get(f"{base}/report?format=md").text
    assert f"| CVSS v4.0 | 9.3 (`{BASE}`) |" in md
    assert f"| CVSS v3.1 | 9.8 (`{v31}`) |" in md

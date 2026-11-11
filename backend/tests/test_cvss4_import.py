"""Nuclei imports keep every vector we can score, CVSS 4.0 included."""

import json

from app.services.importers.parsers import parse_nuclei

V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def _record(template_id: str, cvss: str | None, host: str = "https://www.acme-corp.example") -> str:
    classification = {"cwe-id": ["cwe-89"]}
    if cvss is not None:
        classification["cvss-metrics"] = cvss
    return json.dumps({
        "template-id": template_id,
        "info": {"name": template_id.upper(), "severity": "high", "classification": classification},
        "type": "http", "host": host, "matched-at": f"{host}/{template_id}", "ip": "203.0.113.10",
    })


def test_parse_nuclei_keeps_scorable_vectors_only():
    data = "\n".join([
        _record("v4", V4),
        _record("v4-reordered", " CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N "),
        _record("v31", V31),
        _record("v4-incomplete", "CVSS:4.0/AV:N/AC:L"),
        _record("v3-invalid", "CVSS:3.1/AV:N/AC:L"),
        _record("v2", "AV:N/AC:L/Au:N/C:P/I:P/A:P"),
        _record("none", None),
    ]).encode()
    vectors = {i.key: i.cvss_vector for i in parse_nuclei(data).issues}
    assert vectors == {
        "nuclei:v4": V4,
        "nuclei:v4-reordered": "CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N",
        "nuclei:v31": V31,
        "nuclei:v4-incomplete": "",
        "nuclei:v3-invalid": "",
        "nuclei:v2": "",
        "nuclei:none": "",
    }


def test_nuclei_import_scores_cvss4_findings(api, engagement):
    data = "\n".join([_record("sqli-v4", V4), _record("info-leak-v31", V31)]).encode()
    r = api.post(f"/api/engagements/{engagement['id']}/imports/upload", content=data,
                 params={"tool": "nuclei", "filename": "nuclei-v4.jsonl", "skip_out_of_scope": "true"})
    assert r.status_code == 201, r.text
    assert r.json()["stats"]["findings_created"] == 2
    findings = {f["title"]: f for f in api.ok("GET", f"/api/engagements/{engagement['id']}/findings")}
    v4 = findings["SQLI-V4"]
    assert (v4["cvss_vector"], v4["cvss_score"]) == (V4, 9.3)
    v31 = findings["INFO-LEAK-V31"]
    assert (v31["cvss_vector"], v31["cvss_score"]) == (V31, 5.3)

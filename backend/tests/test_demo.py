import sys

from app import demo

from .conftest import SAMPLES


def test_seed_demo_populates_an_engagement(api, vault):
    demo.seed_demo(vault)
    engagements = api.ok("GET", "/api/engagements")
    assert [e["code"] for e in engagements] == [demo.DEMO_CODE]
    base = f"/api/engagements/{engagements[0]['id']}"

    assert api.ok("GET", "/api/profile") == demo.DEMO_PROFILE
    assert [i["tool"] for i in api.ok("GET", f"{base}/imports")] == ["list", "nuclei", "nmap"]
    evidence = api.ok("GET", f"{base}/evidence")
    assert len(evidence) == 4 and len(vault.blob_ids_on_disk()) == 4
    findings = {f["title"]: f for f in api.ok("GET", f"{base}/findings")}
    assert findings["Exposed Git Repository"]["status"] == "confirmed"
    assert findings["Exposed Git Repository"]["evidence_count"] == 1
    assert findings["Internet-exposed RDP with weak administrator password"]["status"] == "draft"
    assert {e["operator"] for e in api.ok("GET", f"{base}/oplog")} == {"Riley Chen"}
    summary = api.ok("GET", f"{base}/summary")
    assert summary["tests_by_status"]["passed"] == 4 and summary["targets_in_scope"] > 0

    html = api.get(f"{base}/report").text
    assert "Exposed Git Repository" in html and "git-config-response.txt" in html
    assert "Riley Chen, Example Security Ltd" in html


def test_seed_demo_is_idempotent_and_keeps_a_real_profile(api, vault):
    profile = {"name": "Sam Okafor", "email": "sam@example.test", "organization": ""}
    api.ok("PUT", "/api/profile", json=profile)
    demo.seed_demo(vault)
    demo.seed_demo(vault)
    assert len(api.ok("GET", "/api/engagements")) == 1
    assert len(vault.blob_ids_on_disk()) == 4
    assert api.ok("GET", "/api/profile") == profile


def test_samples_dir(monkeypatch, tmp_path):
    assert demo.samples_dir() == SAMPLES
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert demo.samples_dir() == tmp_path / "samples"

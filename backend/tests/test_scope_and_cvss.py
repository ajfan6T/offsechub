import pytest

from app.services import cvss
from app.services.scope import ScopeMatcher, normalize_scope_value


class Rule:
    def __init__(self, id, kind, value, rule="include"):
        self.id, self.kind, self.rule = id, kind, rule
        self.value = normalize_scope_value(kind, value)


MATCHER = ScopeMatcher([
    Rule(1, "cidr", "10.0.0.0/24"),
    Rule(2, "ip", "10.0.0.5", "exclude"),
    Rule(3, "wildcard", "*.Example.com"),
    Rule(4, "url", "https://app.test.io/api"),
    Rule(5, "range", "192.168.1.10-192.168.1.20"),
    Rule(6, "domain", "vpn.example.com", "exclude"),
    Rule(7, "cidr", "2001:db8::/64"),
    Rule(8, "other", "arn:aws:iam::123456789012:root"),
])


@pytest.mark.parametrize("value,status", [
    ("10.0.0.1", "in_scope"),
    ("10.0.0.5", "excluded"),
    ("10.0.1.1", "out_of_scope"),
    ("10.0.0.9:443", "in_scope"),
    ("a.example.com", "in_scope"),
    ("A.EXAMPLE.COM.", "in_scope"),
    ("example.com", "out_of_scope"),  # wildcard covers subdomains, not the apex
    ("badexample.com", "out_of_scope"),
    ("vpn.example.com", "excluded"),
    ("https://vpn.example.com/login", "excluded"),
    ("https://a.example.com:8443/x", "in_scope"),
    ("https://app.test.io/api", "in_scope"),
    ("https://app.test.io/api/v1/users", "in_scope"),
    ("https://app.test.io/apix", "out_of_scope"),
    ("http://app.test.io/api", "out_of_scope"),
    ("192.168.1.15", "in_scope"),
    ("192.168.1.21", "out_of_scope"),
    ("2001:db8::1", "in_scope"),
    ("[2001:db8::1]:443", "in_scope"),
    ("arn:aws:iam::123456789012:ROOT", "in_scope"),
    ("garbage value !!", "out_of_scope"),
])
def test_scope_matching(value, status):
    assert MATCHER.check(value).status == status


def test_target_with_multiple_identifiers():
    # Hostname in scope via wildcard, IP excluded -> exclusion wins.
    assert MATCHER.check_target("a.example.com", "10.0.0.5") == "excluded"
    assert MATCHER.check_target("host.other.org", "10.0.0.7") == "in_scope"


@pytest.mark.parametrize("kind,value", [
    ("ip", "10.0.0.300"), ("cidr", "10.0.0.0/33"), ("range", "10.0.0.9-10.0.0.1"),
    ("range", "10.0.0.1-2001:db8::1"), ("wildcard", "example.com"), ("domain", "bad domain"),
    ("url", "ftp://x.example"), ("url", "not a url"),
])
def test_invalid_scope_values(kind, value):
    with pytest.raises(ValueError):
        normalize_scope_value(kind, value)


def test_scope_api_normalises_and_checks(admin, engagement):
    base = f"/api/engagements/{engagement['id']}/scope"
    item = admin.ok("POST", base, json={"kind": "cidr", "value": "198.51.100.77/24"})
    assert item["value"] == "198.51.100.0/24"
    assert admin.post(base, json={"kind": "cidr", "value": "198.51.100.0/24"}).status_code == 409
    assert admin.post(base, json={"kind": "ip", "value": "nope"}).status_code == 422
    results = admin.ok("POST", f"{base}/check", status=200,
                       json={"values": ["203.0.113.3", "203.0.113.11", "8.8.8.8", "x.acme-corp.example"]})
    assert [r["status"] for r in results] == ["in_scope", "excluded", "out_of_scope", "in_scope"]


@pytest.mark.parametrize("vector,score,severity", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "medium"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "medium"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "low"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "info"),
    ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 6.8, "medium"),
])
def test_cvss_base_scores(vector, score, severity):
    r = cvss.calculate(vector)
    assert (r.score, r.severity) == (score, severity)


def test_cvss_canonicalises_order_and_keeps_temporal():
    r = cvss.calculate("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N/E:P")
    assert r.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P"


@pytest.mark.parametrize("vector", [
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",           # missing prefix
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",       # missing A
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # bad value
    "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicate
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",  # unknown metric
])
def test_cvss_rejects_invalid(vector):
    with pytest.raises(cvss.CvssError):
        cvss.calculate(vector)


def test_cvss_endpoint(admin):
    r = admin.ok("POST", "/api/cvss", status=200, json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert r["score"] == 9.8 and r["severity"] == "critical"
    assert admin.post("/api/cvss", json={"vector": "junk"}).status_code == 422

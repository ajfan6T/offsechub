"""Engagement-level access control."""

from .conftest import user_id


def _add_member(admin, eng, email, role):
    admin.ok("PUT", f"/api/engagements/{eng['id']}/members",
             json={"user_id": user_id(admin, email), "role": role})


def test_non_member_cannot_see_engagement(admin, make_user, engagement):
    outsider = make_user("out@test.local")
    assert outsider.ok("GET", "/api/engagements") == []
    assert outsider.get(f"/api/engagements/{engagement['id']}").status_code == 404
    assert outsider.get(f"/api/engagements/{engagement['id']}/findings").status_code == 404
    assert outsider.ok("GET", "/api/clients") == []


def test_viewer_is_read_only(admin, make_user, engagement):
    viewer = make_user("v@test.local", role="viewer")
    _add_member(admin, engagement, "v@test.local", "viewer")
    base = f"/api/engagements/{engagement['id']}"
    assert viewer.ok("GET", base)["my_role"] == "viewer"
    assert viewer.post(f"{base}/targets", json={"value": "203.0.113.5"}).status_code == 403
    assert viewer.post(f"{base}/findings", json={"title": "x"}).status_code == 403


def test_tester_member_can_work_but_not_manage(admin, make_user, engagement):
    tester = make_user("t@test.local")
    _add_member(admin, engagement, "t@test.local", "tester")
    base = f"/api/engagements/{engagement['id']}"
    tester.ok("POST", f"{base}/targets", json={"value": "203.0.113.5"})
    tester.ok("POST", f"{base}/findings", json={"title": "Thing", "severity": "low"})
    # Scope is a contractual boundary: only leads may change it.
    assert tester.post(f"{base}/scope", json={"kind": "ip", "value": "8.8.8.8"}).status_code == 403
    assert tester.patch(base, json={"name": "renamed"}).status_code == 403
    assert tester.delete(base).status_code == 403


def test_global_viewer_cannot_write_even_as_tester_member(admin, make_user, engagement):
    viewer = make_user("gv@test.local", role="viewer")
    _add_member(admin, engagement, "gv@test.local", "tester")
    r = viewer.post(f"/api/engagements/{engagement['id']}/targets", json={"value": "203.0.113.5"})
    assert r.status_code == 403


def test_tester_cannot_create_engagements_or_clients(admin, make_user):
    tester = make_user("t@test.local")
    assert tester.post("/api/clients", json={"name": "X"}).status_code == 403
    assert tester.get("/api/users").status_code == 403
    assert tester.ok("GET", "/api/users/directory")


def test_lead_creates_engagement_and_becomes_lead(admin, make_user):
    lead = make_user("lead@test.local", role="lead")
    client = lead.ok("POST", "/api/clients", json={"name": "Initech"})
    eng = lead.ok("POST", "/api/engagements", json={
        "client_id": client["id"], "name": "Web", "code": "ini-web", "type": "web_application"})
    assert eng["code"] == "INI-WEB" and eng["my_role"] == "lead"
    members = lead.ok("GET", f"/api/engagements/{eng['id']}/members")
    assert [m["role"] for m in members] == ["lead"]
    # Last lead cannot be removed or demoted.
    uid = members[0]["user"]["id"]
    assert lead.delete(f"/api/engagements/{eng['id']}/members/{uid}").status_code == 400


def test_objects_are_scoped_to_their_engagement(admin, engagement):
    other_client = admin.ok("POST", "/api/clients", json={"name": "Other"})
    other = admin.ok("POST", "/api/engagements", json={
        "client_id": other_client["id"], "name": "Other", "code": "OTHER", "type": "api"})
    f = admin.ok("POST", f"/api/engagements/{engagement['id']}/findings", json={"title": "Secret"})
    t = admin.ok("POST", f"/api/engagements/{engagement['id']}/targets", json={"value": "203.0.113.2"})
    assert admin.get(f"/api/engagements/{other['id']}/findings/{f['id']}").status_code == 404
    # Linking a target from another engagement is refused.
    r = admin.post(f"/api/engagements/{other['id']}/findings", json={"title": "x", "target_ids": [t["id"]]})
    assert r.status_code == 404


def test_duplicate_engagement_code(admin, engagement):
    r = admin.post("/api/engagements", json={"client_id": engagement["client"]["id"], "name": "x",
                                             "code": "acme-ext", "type": "api"})
    assert r.status_code == 409


def test_end_date_before_start(admin, engagement):
    r = admin.patch(f"/api/engagements/{engagement['id']}", json={"end_date": "2026-08-01"})
    assert r.status_code == 422

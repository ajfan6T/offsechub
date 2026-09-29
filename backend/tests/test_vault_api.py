"""The vault and app endpoints: lifecycle, secrets, settings, profile and recents."""

import time

import pytest

from .conftest import PASSWORD, Api

NEW_PASSWORD = "an even longer passphrase"


def _unlock(client, path, **secret):
    return client.ok("POST", "/api/vault/unlock", status=200, json={"path": path, **secret})


def _refused(client, path, **secret) -> bool:
    return client.post("/api/vault/unlock", json={"path": path, **secret}).status_code == 400


def _relock(client):
    assert client.ok("POST", "/api/vault/lock", status=200)["state"] == "locked"


def test_create_vault(anon, tmp_path):
    assert anon.ok("GET", "/api/vault/status")["state"] == "none"
    body = anon.ok("POST", "/api/vault/create",
                   json={"path": str(tmp_path / "acme"), "password": PASSWORD})
    assert body["recovery_key"].startswith("OHRK-")
    status = body["status"]
    assert status["state"] == "unlocked" and status["name"] == "acme"
    assert status["path"].endswith("acme.ohvault") and not status["must_set_password"]
    assert (tmp_path / "acme.ohvault" / "vault.json").exists()
    assert anon.ok("GET", "/api/engagements") == []

    busy = tmp_path / "busy.ohvault"
    busy.mkdir()
    (busy / "file").write_text("x")
    r = anon.post("/api/vault/create", json={"path": str(busy), "password": PASSWORD})
    assert r.status_code == 400
    r = anon.post("/api/vault/create", json={"path": str(tmp_path / "weak"), "password": "short"})
    assert r.status_code == 400


def test_lock_unlock_and_wrong_password(api):
    api.ok("POST", "/api/clients", json={"name": "ACME"})
    _relock(api)
    assert api.get("/api/clients").status_code == 423
    assert _refused(api, api.vault_path, password="not the password")
    assert api.post("/api/vault/unlock", json={"path": api.vault_path}).status_code == 422
    assert _unlock(api, api.vault_path, password=PASSWORD)["state"] == "unlocked"
    assert [c["name"] for c in api.ok("GET", "/api/clients")] == ["ACME"]


def test_domain_endpoints_are_locked_out(api, engagement):
    base = f"/api/engagements/{engagement['id']}"
    _relock(api)
    for method, url, kw in [
        ("GET", "/api/engagements", {}),
        ("GET", "/api/dashboard", {}),
        ("GET", "/api/activity", {}),
        ("GET", "/api/finding-templates", {}),
        ("GET", "/api/methodologies", {}),
        ("POST", "/api/cvss", {"json": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}),
        ("GET", f"{base}/targets", {}),
        ("POST", f"{base}/findings", {"json": {"title": "x"}}),
        ("GET", f"{base}/evidence/1/download", {}),
        ("POST", f"{base}/evidence/upload?filename=a.txt", {"content": b"secret"}),
        ("POST", f"{base}/imports/upload?tool=list", {"content": b"10.0.0.1"}),
        ("GET", f"{base}/report", {}),
        ("GET", f"{base}/oplog/export.csv", {}),
        ("GET", "/api/profile", {}),
        ("GET", "/api/vault/settings", {}),
    ]:
        assert api.request(method, url, **kw).status_code == 423, url
    assert api.ok("GET", "/api/health")["status"] == "ok"


def test_recovery_unlock_requires_a_new_password(api):
    old_key = api.recovery_key
    assert api.post("/api/vault/reset-password",
                    json={"recovery_key": old_key, "new_password": NEW_PASSWORD}).status_code == 409
    _relock(api)
    assert _refused(api, api.vault_path, recovery_key="OHRK-AAAA-BBBB")
    status = _unlock(api, api.vault_path, recovery_key=old_key)
    assert status["must_set_password"]

    r = api.post("/api/vault/reset-password", json={"recovery_key": old_key, "new_password": "short"})
    assert r.status_code == 422
    new_key = api.ok("POST", "/api/vault/reset-password", status=200,
                     json={"recovery_key": old_key, "new_password": NEW_PASSWORD})["recovery_key"]
    assert new_key != old_key
    assert not api.ok("GET", "/api/vault/status")["must_set_password"]

    # The typed-in recovery key and the old password are both revoked.
    _relock(api)
    assert _refused(api, api.vault_path, recovery_key=old_key)
    assert _refused(api, api.vault_path, password=PASSWORD)
    _unlock(api, api.vault_path, recovery_key=new_key)
    _relock(api)
    _unlock(api, api.vault_path, password=NEW_PASSWORD)


def test_change_password(api):
    wrong = {"current_password": "wrong password here", "new_password": NEW_PASSWORD}
    assert api.post("/api/vault/change-password", json=wrong).status_code == 400
    weak = {"current_password": PASSWORD, "new_password": "short"}
    assert api.post("/api/vault/change-password", json=weak).status_code == 422
    api.ok("POST", "/api/vault/change-password", status=204,
           json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    _relock(api)
    assert _refused(api, api.vault_path, password=PASSWORD)
    _unlock(api, api.vault_path, password=NEW_PASSWORD)
    assert any(e["summary"] == "Changed vault password" for e in api.ok("GET", "/api/activity"))


def test_rotate_recovery_key(api):
    old_key = api.recovery_key
    r = api.post("/api/vault/recovery-key", json={"password": "wrong password here"})
    assert r.status_code == 400
    new_key = api.ok("POST", "/api/vault/recovery-key", status=200,
                     json={"password": PASSWORD})["recovery_key"]
    assert new_key != old_key
    _relock(api)
    assert _refused(api, api.vault_path, recovery_key=old_key)
    assert _unlock(api, api.vault_path, recovery_key=new_key)["must_set_password"]


def test_rekey_keeps_data_and_revokes_the_old_recovery_key(api, engagement):
    ev = api.ok("POST", f"/api/engagements/{engagement['id']}/evidence/text",
                json={"filename": "proof.txt", "content": "evidence written under the old key"})
    assert api.post("/api/vault/rekey", json={"password": "wrong password here"}).status_code == 400
    new_key = api.ok("POST", "/api/vault/rekey", status=200, json={"password": PASSWORD})["recovery_key"]
    assert new_key != api.recovery_key
    _relock(api)
    assert _refused(api, api.vault_path, recovery_key=api.recovery_key)
    _unlock(api, api.vault_path, password=PASSWORD)
    assert [e["code"] for e in api.ok("GET", "/api/engagements")] == ["ACME-EXT"]
    download = api.get(f"/api/engagements/{engagement['id']}/evidence/{ev['id']}/download")
    assert download.text == "evidence written under the old key"


@pytest.mark.parametrize("minutes,status", [(0, 200), (30, 200), (480, 200), (481, 422), (-1, 422)])
def test_auto_lock_setting_bounds(api, app_ctx, minutes, status):
    r = api.put("/api/vault/settings", json={"auto_lock_minutes": minutes})
    assert r.status_code == status
    if status == 200:
        assert api.ok("GET", "/api/vault/settings") == {"auto_lock_minutes": minutes}
        assert app_ctx[1].auto_lock_minutes == minutes
        assert api.ok("GET", "/api/vault/status")["auto_lock_minutes"] == minutes


def test_auto_lock_setting_is_stored_in_the_vault(api, app_ctx):
    api.ok("PUT", "/api/vault/settings", json={"auto_lock_minutes": 45})
    _relock(api)
    app_ctx[1].auto_lock_minutes = 15
    _unlock(api, api.vault_path, password=PASSWORD)
    assert api.ok("GET", "/api/vault/settings") == {"auto_lock_minutes": 45}


def test_profile(api):
    assert api.ok("GET", "/api/profile") == {"name": "", "email": "", "organization": ""}
    profile = {"name": "Riley Chen", "email": "riley@example-security.test",
               "organization": "Example Security Ltd"}
    assert api.ok("PUT", "/api/profile", json=profile) == profile
    _relock(api)
    _unlock(api, api.vault_path, password=PASSWORD)
    assert api.ok("GET", "/api/profile") == profile
    assert api.put("/api/profile", json={"name": "x" * 256}).status_code == 422


def test_recent_vaults_forget_and_preferences(api, tmp_path):
    recent = api.ok("GET", "/api/app/recent")
    assert recent["remember_recent"] is True
    assert recent["vaults"] == [{"path": api.vault_path, "name": "test", "exists": True}]

    api.ok("POST", "/api/vault/create", json={"path": str(tmp_path / "second"), "password": PASSWORD})
    assert [v["name"] for v in api.ok("GET", "/api/app/recent")["vaults"]] == ["second", "test"]
    api.ok("POST", "/api/app/recent/forget", status=204, json={"path": api.vault_path})
    assert [v["name"] for v in api.ok("GET", "/api/app/recent")["vaults"]] == ["second"]
    api.ok("POST", "/api/app/recent/forget", status=204, json={})
    assert api.ok("GET", "/api/app/recent")["vaults"] == []

    api.ok("PUT", "/api/app/preferences", status=204, json={"remember_recent": False})
    _relock(api)
    _unlock(api, api.vault_path, password=PASSWORD)
    assert api.ok("GET", "/api/app/recent") == {"remember_recent": False, "vaults": []}


def test_close_returns_to_the_picker(api):
    assert api.ok("POST", "/api/vault/close", status=200)["state"] == "none"
    assert api.get("/api/engagements").status_code == 423


def test_status_polling_does_not_keep_the_vault_open(api, app_ctx):
    manager = app_ctx[1]
    manager.last_activity = stale = time.monotonic() - 600
    api.ok("GET", "/api/vault/status")
    api.ok("GET", "/api/engagements")  # background reads don't count either
    assert manager.last_activity == stale
    api.ok("POST", "/api/app/activity", status=204)
    assert manager.last_activity > stale


def test_launch_link_is_cli_only(api, app_ctx):
    app, _manager, auth = app_ctx
    app.state.port = 43210
    assert api.post("/api/app/launch-link").status_code == 403  # cookie (the UI)
    cli = Api(app)
    cli.headers["Authorization"] = f"Bearer {auth.api_token}"
    url = cli.ok("POST", "/api/app/launch-link", status=200)["url"]
    assert url.startswith("http://127.0.0.1:43210/_launch?token=")
    # The link works exactly once, in a fresh browser.
    browser = Api(app)
    token_path = url.removeprefix("http://127.0.0.1:43210")
    assert browser.get(token_path, follow_redirects=False).status_code == 303
    assert Api(app).get(token_path, follow_redirects=False).status_code == 403


def test_app_info(api):
    info = api.ok("GET", "/api/app/info")
    assert {"version", "desktop", "platform", "default_vault_dir"} <= set(info)
    assert info["desktop"] is False

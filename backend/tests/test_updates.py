"""The manual update check (app/services/updates.py)."""

import io
import json
import urllib.error

import pytest

from app import __version__
from app.services import updates


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_returning(payload):
    seen = {}

    def opener(request, timeout):
        seen["url"], seen["headers"], seen["timeout"] = request.full_url, dict(request.header_items()), timeout
        return FakeResponse(json.dumps(payload).encode())

    return opener, seen


def test_newer_release_is_reported():
    opener, seen = opener_returning({"tag_name": "v99.1.0", "published_at": "2027-01-02T03:04:05Z"})
    out = updates.fetch_latest(opener)
    assert out == {"current": __version__, "latest": "99.1.0", "newer": True,
                   "published_at": "2027-01-02T03:04:05Z", "download_url": updates.DOWNLOAD_PAGE}
    assert seen["url"] == updates.LATEST_URL and seen["timeout"] == updates.TIMEOUT_S
    assert seen["headers"]["User-agent"] == f"OffsecHub/{__version__}"


def test_same_or_older_release_is_not_newer():
    for tag in (f"v{__version__}", "v0.0.1", __version__):
        opener, _ = opener_returning({"tag_name": tag})
        assert updates.fetch_latest(opener)["newer"] is False


def test_versions_compare_numerically():
    assert updates.parse_version("v0.10.0") > updates.parse_version("0.9.9")


@pytest.mark.parametrize("payload, message", [({"no": "tag"}, "unexpected answer"),
                                               ({"tag_name": "nightly"}, "unexpected version")])
def test_bad_answers(payload, message):
    opener, _ = opener_returning(payload)
    with pytest.raises(updates.UpdateCheckFailed, match=message):
        updates.fetch_latest(opener)


def test_network_errors_are_reported():
    def offline(request, timeout):
        raise urllib.error.URLError("no route to host")

    with pytest.raises(updates.UpdateCheckFailed, match="could not reach GitHub"):
        updates.fetch_latest(offline)


def test_endpoint_reports_failures_as_502(api, monkeypatch):
    def fail(*_a, **_k):
        raise updates.UpdateCheckFailed("could not reach GitHub (offline)")

    monkeypatch.setattr(updates, "fetch_latest", fail)
    r = api.post("/api/app/update-check")
    assert r.status_code == 502 and "offline" in r.json()["detail"]
    monkeypatch.setattr(updates, "fetch_latest", lambda: {"current": "0.3.0", "latest": "0.4.0", "newer": True,
                                                          "published_at": "", "download_url": "x"})
    assert api.ok("POST", "/api/app/update-check", 200)["latest"] == "0.4.0"

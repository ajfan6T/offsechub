"""The manual update check: the only request OffsecHub ever makes to the internet.

It runs only when the user clicks "Check for updates" in Settings. It asks
GitHub's public API for the latest release of the project and compares
version numbers. It sends nothing about the vault or the user beyond what any
HTTPS request carries (the IP address, and a User-Agent naming the version),
and it never downloads or installs anything.
"""

import json
import re
import urllib.error
import urllib.request

from .. import __version__

LATEST_URL = "https://api.github.com/repos/ajfan6T/offsechub/releases/latest"
DOWNLOAD_PAGE = "https://ajfan6t.github.io/offsechub/#download"
TIMEOUT_S = 10
MAX_BYTES = 256 * 1024


class UpdateCheckFailed(Exception):
    pass


def parse_version(text: str) -> tuple[int, ...]:
    m = re.match(r"v?(\d+(?:\.\d+)*)", text.strip())
    if not m:
        raise UpdateCheckFailed(f"unexpected version {text!r}")
    return tuple(int(x) for x in m.group(1).split("."))


def fetch_latest(opener=urllib.request.urlopen) -> dict:
    request = urllib.request.Request(LATEST_URL, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": f"OffsecHub/{__version__}",
    })
    try:
        with opener(request, timeout=TIMEOUT_S) as resp:
            body = resp.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise UpdateCheckFailed(f"GitHub answered {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateCheckFailed(f"could not reach GitHub ({getattr(exc, 'reason', exc)})") from None
    if len(body) > MAX_BYTES:
        raise UpdateCheckFailed("unexpectedly large answer from GitHub")
    try:
        data = json.loads(body)
        tag = str(data["tag_name"])
    except (ValueError, KeyError, TypeError):
        raise UpdateCheckFailed("unexpected answer from GitHub") from None
    latest = parse_version(tag)
    return {
        "current": __version__,
        "latest": ".".join(map(str, latest)),
        "newer": latest > parse_version(__version__),
        "published_at": str(data.get("published_at") or ""),
        "download_url": DOWNLOAD_PAGE,
    }

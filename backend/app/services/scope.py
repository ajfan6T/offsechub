"""Scope rules: normalisation and matching.

Semantics:
  * ``ip``       single address                     10.0.0.5
  * ``cidr``     network                            10.0.0.0/24
  * ``range``    inclusive address range            10.0.0.10-10.0.0.50
  * ``domain``   exact hostname                     app.example.com
  * ``wildcard`` any *subdomain* (not the apex)     *.example.com
  * ``url``      URL prefix on a path boundary      https://app.example.com/api
  * ``other``    free text, case-insensitive exact  (cloud account IDs, app bundle IDs)

Exclusions always win over inclusions. Anything that matches no include rule
is out of scope, so an engagement with no scope defined has nothing in scope.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Protocol
from urllib.parse import urlsplit

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$"
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class RuleLike(Protocol):
    id: int
    kind: str
    value: str
    rule: str


def _normalize_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not _HOST_RE.match(host):
        raise ValueError(f"invalid hostname: {value!r}")
    return host


def _normalize_url(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("URL must be absolute http(s)://host/...")
    host = parts.hostname.lower()
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or "/"
    return f"{parts.scheme.lower()}://{host}{port}{path}"


def normalize_scope_value(kind: str, value: str) -> str:
    """Validate a scope value for its kind and return the canonical form."""
    value = value.strip()
    if not value:
        raise ValueError("value is required")
    if kind == "ip":
        return str(ipaddress.ip_address(value))
    if kind == "cidr":
        return str(ipaddress.ip_network(value, strict=False))
    if kind == "range":
        try:
            start_s, end_s = (p.strip() for p in value.split("-", 1))
        except ValueError:
            raise ValueError("range must look like 10.0.0.1-10.0.0.50") from None
        start, end = ipaddress.ip_address(start_s), ipaddress.ip_address(end_s)
        if start.version != end.version or int(start) > int(end):
            raise ValueError("range start must be <= end and the same IP version")
        return f"{start}-{end}"
    if kind == "domain":
        return _normalize_host(value)
    if kind == "wildcard":
        if not value.startswith("*."):
            raise ValueError("wildcard must look like *.example.com")
        return "*." + _normalize_host(value[2:])
    if kind == "url":
        return _normalize_url(value)
    if kind == "other":
        return value
    raise ValueError(f"unknown scope kind: {kind}")


@dataclass(frozen=True)
class Identifier:
    """A value to test against scope, parsed into whatever forms it supports."""

    raw: str
    ip: IPAddress | None = None
    host: str | None = None
    url: str | None = None


def parse_identifier(value: str) -> Identifier:
    raw = value.strip()
    candidate = raw
    if "://" in candidate:
        try:
            url = _normalize_url(candidate)
        except ValueError:
            return Identifier(raw=raw)
        host = urlsplit(url).hostname or ""
        return Identifier(raw=raw, url=url, **_host_or_ip(host))
    # Strip a trailing :port from host:port / [v6]:port forms.
    m = re.match(r"^\[([0-9a-fA-F:.]+)\](?::\d+)?$", candidate)
    if m:
        candidate = m.group(1)
    elif candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]
    return Identifier(raw=raw, **_host_or_ip(candidate))


def _host_or_ip(value: str) -> dict:
    try:
        return {"ip": ipaddress.ip_address(value)}
    except ValueError:
        pass
    try:
        return {"host": _normalize_host(value)}
    except ValueError:
        return {}


def _url_prefix_match(rule_url: str, url: str) -> bool:
    if not url.startswith(rule_url):
        return False
    if rule_url.endswith("/") or len(url) == len(rule_url):
        return True
    return url[len(rule_url)] in "/?#"


def rule_matches(kind: str, rule_value: str, ident: Identifier) -> bool:
    if kind == "ip":
        return ident.ip is not None and ident.ip == ipaddress.ip_address(rule_value)
    if kind == "cidr":
        net = ipaddress.ip_network(rule_value)
        return ident.ip is not None and ident.ip.version == net.version and ident.ip in net
    if kind == "range":
        start_s, end_s = rule_value.split("-", 1)
        start, end = ipaddress.ip_address(start_s), ipaddress.ip_address(end_s)
        return (
            ident.ip is not None
            and ident.ip.version == start.version
            and int(start) <= int(ident.ip) <= int(end)
        )
    if kind == "domain":
        return ident.host is not None and ident.host == rule_value
    if kind == "wildcard":
        return ident.host is not None and ident.host.endswith("." + rule_value[2:])
    if kind == "url":
        return ident.url is not None and _url_prefix_match(rule_value, ident.url)
    if kind == "other":
        return ident.raw.lower() == rule_value.lower()
    return False


@dataclass
class ScopeDecision:
    value: str
    status: str  # in_scope | out_of_scope | excluded
    rule_id: int | None
    reason: str


class ScopeMatcher:
    def __init__(self, rules: Iterable[RuleLike]):
        rules = list(rules)
        self.excludes = [r for r in rules if r.rule == "exclude"]
        self.includes = [r for r in rules if r.rule == "include"]

    def check(self, value: str) -> ScopeDecision:
        ident = parse_identifier(value)
        for r in self.excludes:
            if rule_matches(r.kind, r.value, ident):
                return ScopeDecision(value, "excluded", r.id, f"excluded by {r.kind} {r.value}")
        for r in self.includes:
            if rule_matches(r.kind, r.value, ident):
                return ScopeDecision(value, "in_scope", r.id, f"included by {r.kind} {r.value}")
        return ScopeDecision(value, "out_of_scope", None, "matches no include rule")

    def check_target(self, *identifiers: str) -> str:
        """Scope status for an asset known by several identifiers (value, IP, hostname).

        Any exclusion wins; otherwise in scope if any identifier is included.
        """
        statuses = [self.check(i).status for i in identifiers if i]
        if "excluded" in statuses:
            return "excluded"
        if "in_scope" in statuses:
            return "in_scope"
        return "out_of_scope"

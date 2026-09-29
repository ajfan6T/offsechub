"""Parsers for recon/scanner output. Pure functions: bytes in, dataclasses out.

XML is parsed with defusedxml because tool output is untrusted input (a
target can influence banners, hostnames and HTTP responses that end up in it).
"""

import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from defusedxml import ElementTree as SafeET

from ..scope import parse_identifier


class ParseError(ValueError):
    pass


@dataclass
class ParsedService:
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""


@dataclass
class ParsedHost:
    value: str
    kind: str = "host"
    ip: str = ""
    hostname: str = ""
    os: str = ""
    services: list[ParsedService] = field(default_factory=list)


@dataclass
class ParsedIssue:
    """A scanner result that should become (or merge into) a draft finding."""

    key: str
    title: str
    severity: str
    host: ParsedHost
    matched_at: str
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str = ""
    cvss_vector: str = ""
    reproduction: str = ""


@dataclass
class ParseResult:
    hosts: list[ParsedHost] = field(default_factory=list)
    issues: list[ParsedIssue] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------- nmap

_OPEN_STATES = {"open", "open|filtered"}


def parse_nmap_xml(data: bytes) -> ParseResult:
    try:
        root = SafeET.fromstring(data)
    except Exception as exc:  # defusedxml raises several exception types
        raise ParseError(f"not valid Nmap XML: {exc}") from None
    if root.tag != "nmaprun":
        raise ParseError("not an Nmap XML report (missing <nmaprun>)")

    result = ParseResult()
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        hostnames = [h.get("name", "") for h in host_el.findall("hostnames/hostname")]
        hostname = next((h for h in hostnames if h), "")
        if not ip and not hostname:
            continue

        os_name = ""
        matches = host_el.findall("os/osmatch")
        if matches:
            best = max(matches, key=lambda o: int(o.get("accuracy", "0") or 0))
            os_name = best.get("name", "")

        services = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state not in _OPEN_STATES:
                continue
            svc = port_el.find("service")
            get = (lambda k: svc.get(k, "")) if svc is not None else (lambda k: "")
            try:
                port = int(port_el.get("portid", ""))
            except ValueError:
                result.errors.append(f"bad port id on host {ip or hostname}")
                continue
            services.append(
                ParsedService(
                    port=port,
                    protocol=port_el.get("protocol", "tcp"),
                    state=state,
                    name=get("name"),
                    product=get("product"),
                    version=get("version"),
                    extra_info=get("extrainfo"),
                )
            )

        result.hosts.append(
            ParsedHost(
                value=ip or hostname,
                ip=ip,
                hostname=hostname,
                os=os_name,
                services=services,
            )
        )
    return result


# -------------------------------------------------------------------- nuclei

_NUCLEI_SEVERITY = {"critical", "high", "medium", "low", "info"}


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _nuclei_host(record: dict) -> ParsedHost:
    host = str(record.get("host") or record.get("matched-at") or "")
    ip = str(record.get("ip") or "")
    if "://" in host:
        parts = urlsplit(host)
        origin = f"{parts.scheme}://{parts.netloc}"
        return ParsedHost(value=origin, kind="web", hostname=parts.hostname or "", ip=ip)
    ident = parse_identifier(host)
    if ident.ip is not None:
        return ParsedHost(value=str(ident.ip), ip=str(ident.ip))
    if ident.host:
        return ParsedHost(value=ident.host, kind="domain", hostname=ident.host, ip=ip)
    return ParsedHost(value=host or ip, ip=ip)


def parse_nuclei(data: bytes) -> ParseResult:
    text = data.decode("utf-8", errors="replace").strip()
    records: list = []
    result = ParseResult()
    if text.startswith("["):
        try:
            records = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"not valid nuclei JSON export: {exc}") from None
    else:
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                result.errors.append(f"line {lineno}: invalid JSON")
    if not records and not result.errors:
        raise ParseError("no nuclei results found")

    for rec in records:
        if not isinstance(rec, dict) or "template-id" not in rec:
            result.errors.append("skipped record without template-id")
            continue
        info = rec.get("info") or {}
        classification = info.get("classification") or {}
        severity = str(info.get("severity", "info")).lower()
        host = _nuclei_host(rec)
        matched_at = str(rec.get("matched-at") or rec.get("host") or "")

        cwe = ""
        cwe_ids = _as_list(classification.get("cwe-id"))
        if cwe_ids:
            cwe = str(cwe_ids[0]).upper()
        cvss = str(classification.get("cvss-metrics") or "")
        refs = [str(r) for r in _as_list(info.get("reference")) if r]
        refs += [str(c) for c in _as_list(classification.get("cve-id")) if c]

        repro = [f"Matched at: {matched_at}"]
        extracted = _as_list(rec.get("extracted-results"))
        if extracted:
            repro.append("Extracted: " + ", ".join(str(e) for e in extracted[:10]))
        if rec.get("curl-command"):
            repro.append(f"Reproduce: {rec['curl-command']}")

        result.hosts.append(host)
        result.issues.append(
            ParsedIssue(
                key=f"nuclei:{rec['template-id']}",
                title=str(info.get("name") or rec["template-id"]),
                severity=severity if severity in _NUCLEI_SEVERITY else "info",
                host=host,
                matched_at=matched_at,
                description=str(info.get("description") or "").strip(),
                remediation=str(info.get("remediation") or "").strip(),
                references=refs,
                cwe=cwe,
                cvss_vector=cvss if cvss.startswith("CVSS:3") else "",
                reproduction="\n".join(repro),
            )
        )
    return result


# --------------------------------------------------------------- plain lists


def parse_list(data: bytes) -> ParseResult:
    """One host, IP or URL per line, e.g. subfinder, amass, dnsx or httpx output."""
    result = ParseResult()
    seen: set[str] = set()
    for lineno, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        ident = parse_identifier(token)
        if ident.url:
            parts = urlsplit(ident.url)
            host = ParsedHost(value=ident.url.rstrip("/") if parts.path == "/" else ident.url,
                              kind="web", hostname=ident.host or "",
                              ip=str(ident.ip) if ident.ip else "")
        elif ident.ip is not None:
            host = ParsedHost(value=str(ident.ip), ip=str(ident.ip))
        elif ident.host:
            host = ParsedHost(value=ident.host, kind="domain", hostname=ident.host)
        else:
            result.errors.append(f"line {lineno}: not a host, IP or URL: {token[:80]}")
            continue
        if host.value not in seen:
            seen.add(host.value)
            result.hosts.append(host)
    return result


PARSERS = {"nmap": parse_nmap_xml, "nuclei": parse_nuclei, "list": parse_list}

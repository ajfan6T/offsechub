"""Nessus v2 files (.nessus): in Nessus, open the scan and choose Export > Nessus.

Every ReportHost becomes a host, and every port a ReportItem reports on
becomes an open service on it. Plugins with severity 1-4 (Low to Critical)
become draft findings, one per plugin (key ``nessus:<pluginID>``) listing every
affected host. Severity 0 ("None"/informational) plugins, such as service
detection and scan information, are not turned into findings: they only
contribute services.

CVSS: the v3 vector is used when present (Nessus writes ``CVSS:3.0/...``),
else the v4 one; v2 vectors are ignored.
"""

from __future__ import annotations

import ipaddress
import re

from defusedxml import ElementTree as SafeET

from .htmltext import inline_code, text_to_markdown, truncated_block
from .parsers import ParsedHost, ParsedIssue, ParsedService, ParseError, ParseResult

OUTPUT_LIMIT = 4000

_SEVERITY = {1: "low", 2: "medium", 3: "high", 4: "critical"}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE = re.compile(r"^CWE:(\d{1,6})$", re.IGNORECASE)
_URL = re.compile(r"^https?://\S+$", re.IGNORECASE)


def _text(el, tag: str) -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None else ""


def _int(value: str | None) -> int | None:
    try:
        return int((value or "").strip())
    except ValueError:
        return None


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


def _host(report_host) -> ParsedHost | None:
    props = {t.get("name", ""): (t.text or "").strip()
             for t in report_host.findall("HostProperties/tag")}
    name = (report_host.get("name") or "").strip()
    ip = _ip(props.get("host-ip", "")) or _ip(name)
    value = ip or name
    if not value:
        return None
    hostname = props.get("host-fqdn") or props.get("hostname") or ("" if _ip(name) else name)
    os_name = props.get("operating-system", "").split("\n")[0].strip()
    return ParsedHost(value=value, ip=ip, hostname=hostname, os=os_name)


def _cvss(item) -> str:
    v3 = _text(item, "cvss3_vector")
    if v3.startswith("CVSS:3"):
        return v3
    v4 = _text(item, "cvss4_vector")
    return v4 if v4.startswith("CVSS:4") else ""


def _references(item) -> list[str]:
    refs = [u for u in _text(item, "see_also").split() if _URL.match(u)]
    for cve in item.findall("cve"):
        cve_id = (cve.text or "").strip().upper()
        if _CVE.match(cve_id):
            refs.append(f"https://www.cve.org/CVERecord?id={cve_id}")
    return list(dict.fromkeys(refs))


def _cwe(item) -> str:
    for xref in item.findall("xref"):
        m = _CWE.match((xref.text or "").strip())
        if m:
            return f"CWE-{m.group(1)}"
    return ""


def _solution(item) -> str:
    text = _text(item, "solution")
    return "" if text.lower() == "n/a" else text_to_markdown(text)


def parse_nessus(data: bytes) -> ParseResult:
    try:
        root = SafeET.fromstring(data)
    except Exception as exc:  # defusedxml raises several exception types
        raise ParseError(f"not valid Nessus XML: {exc}") from None
    if root.tag != "NessusClientData_v2":
        raise ParseError("not a Nessus v2 file (missing <NessusClientData_v2>)")

    result = ParseResult()
    for report_host in root.findall("Report/ReportHost"):
        host = _host(report_host)
        if host is None:
            result.errors.append("skipped a ReportHost without a name or host-ip")
            continue
        result.hosts.append(host)
        services: dict[tuple[int, str], ParsedService] = {}
        for item in report_host.findall("ReportItem"):
            port = _int(item.get("port"))
            protocol = (item.get("protocol") or "tcp").strip().lower()
            plugin_id = (item.get("pluginID") or "").strip()
            if port is None or not 0 <= port <= 65535:
                result.errors.append(f"bad port on host {host.value} (plugin {plugin_id or '?'})")
                continue
            svc_name = (item.get("svc_name") or "").strip()
            if port > 0:
                svc = services.get((port, protocol))
                if svc is None:
                    services[(port, protocol)] = ParsedService(port, protocol, "open", name=svc_name)
                elif not svc.name:
                    svc.name = svc_name

            severity = _int(item.get("severity"))
            if severity == 0:
                continue
            if severity not in _SEVERITY:
                result.errors.append(f"bad severity on host {host.value} (plugin {plugin_id or '?'})")
                continue
            if not plugin_id:
                result.errors.append(f"skipped a ReportItem without pluginID on host {host.value}")
                continue

            matched_at = f"{host.value}:{port}/{protocol}"
            repro = f"Matched at: {inline_code(matched_at)}"
            out_el = item.find("plugin_output")
            output = (out_el.text or "") if out_el is not None else ""
            if output.strip():
                repro += "\n\n" + truncated_block(output, OUTPUT_LIMIT, what="Plugin output")
            title = " ".join((item.get("pluginName") or _text(item, "plugin_name")).split())
            result.issues.append(
                ParsedIssue(
                    key=f"nessus:{plugin_id[:100]}",
                    title=title or f"Nessus plugin {plugin_id}",
                    severity=_SEVERITY[severity],
                    host=host,
                    matched_at=matched_at,
                    description="\n\n".join(p for p in (
                        text_to_markdown(_text(item, "synopsis")),
                        text_to_markdown(_text(item, "description")),
                    ) if p),
                    remediation=_solution(item),
                    references=_references(item),
                    cwe=_cwe(item),
                    cvss_vector=_cvss(item),
                    reproduction=repro,
                )
            )
        host.services = list(services.values())
    return result

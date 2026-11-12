"""Burp Suite "Report selected issues" XML export.

In Burp, select issues (Target > Site map, or Dashboard), right-click, and
choose Report selected issues > XML. Requests and responses may be included
base64-encoded or not; both are read.

Each issue type becomes one draft finding (key ``burp:<type>``) that lists
every affected host. Issue text is HTML, converted to the Markdown subset by
``htmltext``. Burp has no CVSS, and issues marked "False positive" are skipped.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from urllib.parse import urlsplit

from defusedxml import ElementTree as SafeET

from .htmltext import html_links, html_to_markdown, inline_code, truncated_block
from .parsers import ParsedHost, ParsedIssue, ParseError, ParseResult

REQUEST_LIMIT = 4000

_SEVERITY = {"high": "high", "medium": "medium", "low": "low", "information": "info", "info": "info"}
_CONFIDENCE = {"certain": "Certain", "firm": "Firm", "tentative": "Tentative"}
_CWE = re.compile(r"\bCWE-(\d{1,6})\b", re.IGNORECASE)
# Every issue an extension reports shares this type, so its name tells them apart.
_EXTENSION_TYPE = "134217728"


def _text(el, tag: str) -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None else ""


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


def _web_host(origin: str, ip: str) -> ParsedHost | None:
    try:
        parts = urlsplit(origin.strip())
        hostname = parts.hostname or ""
    except ValueError:  # e.g. an unterminated IPv6 literal
        return None
    if parts.scheme.lower() not in ("http", "https") or not hostname:
        return None
    return ParsedHost(value=f"{parts.scheme}://{parts.netloc}".lower(), kind="web",
                      hostname=hostname, ip=ip)


def _request(issue_el) -> tuple[str, str]:
    """The first recorded request as text, and an error message if it could not be read."""
    for rr in issue_el.findall("requestresponse"):
        req = rr.find("request")
        raw = (req.text or "") if req is not None else ""
        if not raw.strip():
            continue
        if (req.get("base64") or "").lower() != "true":
            return raw, ""
        try:
            data = base64.b64decode("".join(raw.split()), validate=True)
        except (binascii.Error, ValueError):
            return "", "request is not valid base64"
        return data.decode("utf-8", errors="replace"), ""
    return "", ""


def _join(*parts: str) -> str:
    return "\n\n".join(p for p in parts if p)


def parse_burp_xml(data: bytes) -> ParseResult:
    try:
        root = SafeET.fromstring(data)
    except Exception as exc:  # defusedxml raises several exception types
        raise ParseError(f"not valid Burp Suite XML: {exc}") from None
    if root.tag != "issues":
        raise ParseError("not a Burp Suite issues export (missing <issues>)")

    result = ParseResult()
    for n, el in enumerate(root.findall("issue"), 1):
        name = " ".join(_text(el, "name").split())
        severity = _text(el, "severity").lower()
        if severity == "false positive":
            continue
        issue_type = _text(el, "type")
        if not issue_type.isdigit():
            result.errors.append(f"issue {n}: skipped, no issue type")
            continue
        host_el = el.find("host")
        origin = (host_el.text or "") if host_el is not None else ""
        host = _web_host(origin, _ip(host_el.get("ip", "")) if host_el is not None else "")
        if host is None:
            result.errors.append(f"issue {n}: skipped, host is not an http(s) URL")
            continue

        key = f"burp:{issue_type}"
        if issue_type == _EXTENSION_TYPE and name:
            key = f"{key}:{name[:200]}"
        path = _text(el, "path")
        matched_at = host.value + (path if path.startswith("/") else "")
        location = _text(el, "location")

        confidence = _CONFIDENCE.get(_text(el, "confidence").lower(), "")
        classifications = _text(el, "vulnerabilityClassifications")
        cwe = _CWE.search(classifications)
        refs = html_links(_text(el, "references")) + html_links(classifications)

        repro = [f"Matched at: {inline_code(matched_at)}"]
        if location and location != path:
            repro.append(f"Location: {inline_code(location)}")
        repro_text = "\n".join(repro)
        request, error = _request(el)
        if error:
            result.errors.append(f"issue {n} ({name or issue_type}): {error}")
        if request.strip():
            repro_text += "\n\n" + truncated_block(request, REQUEST_LIMIT, lang="http",
                                                   what="Request")

        result.hosts.append(host)
        result.issues.append(
            ParsedIssue(
                key=key,
                title=name or f"Burp Suite issue {issue_type}",
                severity=_SEVERITY.get(severity, "info"),
                host=host,
                matched_at=matched_at,
                description=_join(
                    html_to_markdown(_text(el, "issueBackground")),
                    html_to_markdown(_text(el, "issueDetail")),
                    f"Burp Suite confidence: {confidence}." if confidence else "",
                ),
                remediation=_join(
                    html_to_markdown(_text(el, "remediationBackground")),
                    html_to_markdown(_text(el, "remediationDetail")),
                ),
                references=list(dict.fromkeys(refs)),
                cwe=f"CWE-{cwe.group(1)}" if cwe else "",
                reproduction=repro_text,
            )
        )
    return result

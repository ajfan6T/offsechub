"""Engagement report generation: the shared context, HTML and Markdown.

DOCX (``report_docx``) and PDF (``report_pdf``) render the same context.
"""

import base64
import re
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from ..models import Engagement, Evidence
from ..schemas import REPORTABLE_STATUSES, SEVERITY_ORDER
from ..vault.crypto import CryptoError
from ..vault.manager import BlobIntegrityError
from . import richtext, storage
from .cvss import version_of
from .findings import finding_ref
from .methodologies import load_methodologies
from .scope import ScopeMatcher

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
MAX_EMBED_BYTES = 5 * 1024 * 1024

SEVERITIES = ["critical", "high", "medium", "low", "info"]
ENGAGEMENT_TYPE_LABELS = {
    "external_network": "External Network Penetration Test",
    "internal_network": "Internal Network Penetration Test",
    "web_application": "Web Application Penetration Test",
    "api": "API Penetration Test",
    "mobile": "Mobile Application Penetration Test",
    "cloud": "Cloud Security Assessment",
    "wireless": "Wireless Security Assessment",
    "social_engineering": "Social Engineering Assessment",
    "red_team": "Red Team Engagement",
    "physical": "Physical Security Assessment",
    "other": "Security Assessment",
}

_html_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_md_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=False,
    trim_blocks=True,
    lstrip_blocks=True,
)


def _md_escape_cell(value: str) -> str:
    return (value or "").replace("|", "\\|").replace("\n", " ")


def _byte_count(size: int) -> str:
    return f"{size:,} byte{'' if size == 1 else 's'}"


def _rich(text: str | None) -> Markup:
    """Finding text as escaped HTML (see richtext for the Markdown subset)."""
    return Markup(richtext.to_html(text))


def _rich_steps(text: str | None) -> Markup:
    """Steps to reproduce: unformatted text (often a raw HTTP request) stays a code block."""
    if richtext.is_plain(richtext.parse(text)):
        return Markup('<pre class="steps">{}</pre>').format(text or "")
    return _rich(text)


RETEST_LABELS = {"resolved": "Resolved", "partially_resolved": "Partially resolved",
                 "not_resolved": "Not resolved"}

def _md_steps(text: str | None) -> str:
    """Unformatted steps become a fenced block whose fence no line inside can close."""
    if not richtext.is_plain(richtext.parse(text)):
        return text or ""
    longest = max((len(run) for run in re.findall(r"`+", text or "")), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


_md_env.filters["cell"] = _md_escape_cell
_md_env.filters["steps"] = _md_steps
_html_env.filters["rich"] = _rich
_html_env.filters["rich_steps"] = _rich_steps
for _env in (_html_env, _md_env):
    _env.filters["bytes"] = _byte_count
    _env.globals["retest_labels"] = RETEST_LABELS

ImageReader = Callable[[Evidence], bytes]


def build_context(eng: Engagement, *, profile: dict, include_drafts: bool = False,
                  read_image: ImageReader | None = None, branding: dict | None = None) -> dict:
    """Everything the templates (and the JSON format) need.

    ``read_image`` returns an evidence file's verified plaintext; when given,
    raster images up to 5 MB are embedded (``data`` bytes and a ``data_uri``).
    ``branding`` comes from ``branding.report_branding``.
    """
    statuses = set(REPORTABLE_STATUSES) | ({"draft"} if include_drafts else set())
    findings = sorted(
        (f for f in eng.findings if f.status in statuses),
        key=lambda f: (SEVERITY_ORDER[f.severity], -(f.cvss_score or 0), f.number),
    )
    severity_counts = Counter(f.severity for f in findings)

    finding_rows, fingerprints = [], []
    for f in findings:
        ref = finding_ref(eng, f)
        images, attachments = [], []
        for ev in sorted(f.evidence, key=lambda e: (e.created_at, e.id)):
            item = {"filename": ev.filename, "sha256": ev.sha256, "size": ev.size,
                    "description": ev.description, "content_type": ev.content_type}
            fingerprints.append({"finding": ref, "filename": ev.filename, "size": ev.size,
                                 "sha256": ev.sha256})
            if (read_image and ev.content_type in storage.INLINE_IMAGE_TYPES
                    and ev.size <= MAX_EMBED_BYTES):
                try:
                    data = read_image(ev)  # verified against its fingerprint
                except (FileNotFoundError, BlobIntegrityError, CryptoError):
                    # Never show a picture that isn't the recorded evidence.
                    item["problem"] = "could not be verified; not embedded"
                else:
                    item["data"] = data
                    item["data_uri"] = f"data:{ev.content_type};base64,{base64.b64encode(data).decode()}"
                    images.append(item)
                    continue
            attachments.append(item)
        finding_rows.append({
            "id": f.id,
            "ref": ref,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "cvss_vector": f.cvss_vector,
            "cvss_version": version_of(f.cvss_vector),
            "cvss_score": f.cvss_score,
            "cwe": f.cwe,
            "description": f.description,
            "impact": f.impact,
            "steps_to_reproduce": f.steps_to_reproduce,
            "remediation": f.remediation,
            "references": [r.strip() for r in f.references.splitlines() if r.strip()],
            "targets": [t.value for t in f.targets],
            "images": images,
            "attachments": attachments,
            "retests": [{"tested_on": r.tested_on.isoformat(), "result": r.result,
                         "tester": r.tester, "notes": r.notes} for r in f.retests],
            "retest_status": f.retests[-1].result if f.retests else None,
        })

    methodologies = load_methodologies()
    coverage: dict[str, Counter] = {}
    for tc in eng.test_cases:
        coverage.setdefault(tc.methodology, Counter())[tc.status] += 1
    coverage_rows = [
        {
            "methodology": methodologies.get(m, {}).get("name", m.replace("-", " ").title()),
            "total": sum(c.values()),
            "passed": c["passed"],
            "failed": c["failed"],
            "not_applicable": c["not_applicable"],
            "blocked": c["blocked"],
            "incomplete": c["not_started"] + c["in_progress"],
        }
        for m, c in sorted(coverage.items())
    ]

    matcher = ScopeMatcher(eng.scope_items)
    in_scope_targets = [
        t for t in sorted(eng.targets, key=lambda t: t.value)
        if matcher.check_target(t.value, t.ip, t.hostname) == "in_scope"
    ]

    return {
        "engagement": {
            "name": eng.name,
            "code": eng.code,
            "type": ENGAGEMENT_TYPE_LABELS.get(eng.type, eng.type),
            "status": eng.status,
            "start_date": eng.start_date.isoformat() if eng.start_date else None,
            "end_date": eng.end_date.isoformat() if eng.end_date else None,
            "description": eng.description,
            "rules_of_engagement": eng.rules_of_engagement,
            "executive_summary": eng.executive_summary,
        },
        "client": {"name": eng.client.name, "contact_name": eng.client.contact_name},
        "prepared_by": {k: (profile.get(k) or "").strip() for k in ("name", "organization", "email")},
        "scope": {
            "include": [{"kind": s.kind, "value": s.value, "notes": s.notes}
                        for s in eng.scope_items if s.rule == "include"],
            "exclude": [{"kind": s.kind, "value": s.value, "notes": s.notes}
                        for s in eng.scope_items if s.rule == "exclude"],
        },
        "severity_counts": {s: severity_counts.get(s, 0) for s in SEVERITIES},
        "total_findings": len(findings),
        "findings": finding_rows,
        "evidence_fingerprints": fingerprints,
        "coverage": coverage_rows,
        "targets": [
            {
                "value": t.value,
                "hostname": t.hostname,
                "ip": t.ip,
                "os": t.os,
                "status": t.status,
                "services": [f"{s.port}/{s.protocol} {s.name} {s.product} {s.version}".strip()
                             for s in t.services],
            }
            for t in in_scope_targets
        ],
        "branding": branding or {"organization": (profile.get("organization") or "").strip(),
                                 "accent": "#0f766e", "classification": "CONFIDENTIAL",
                                 "footer": "", "logo": None, "logo_content_type": None,
                                 "logo_data_uri": None},
        "retested": any(f.retests for f in findings),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "draft": include_drafts or eng.status not in ("delivered", "closed"),
    }


def json_safe(context: dict) -> dict:
    """The context without raw bytes (image data, the logo), for the JSON format."""
    out = {**context, "branding": {k: v for k, v in context["branding"].items()
                                   if k not in ("logo", "logo_data_uri")}}
    out["findings"] = [
        {**f, "images": [{k: v for k, v in i.items() if k not in ("data", "data_uri")}
                         for i in f["images"]]}
        for f in context["findings"]
    ]
    return out


def render_html(context: dict) -> str:
    return _html_env.get_template("report.html.j2").render(**context)


def render_markdown(context: dict) -> str:
    return _md_env.get_template("report.md.j2").render(**context)

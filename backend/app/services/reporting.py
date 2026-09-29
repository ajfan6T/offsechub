"""Engagement report generation (HTML, Markdown, JSON)."""

import base64
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Engagement, User
from ..schemas import REPORTABLE_STATUSES, SEVERITY_ORDER
from . import storage
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


_md_env.filters["cell"] = _md_escape_cell


def build_context(eng: Engagement, user: User, include_drafts: bool, embed_images: bool) -> dict:
    statuses = set(REPORTABLE_STATUSES) | ({"draft"} if include_drafts else set())
    findings = sorted(
        (f for f in eng.findings if f.status in statuses),
        key=lambda f: (SEVERITY_ORDER[f.severity], -(f.cvss_score or 0), f.number),
    )
    severity_counts = Counter(f.severity for f in findings)

    finding_rows = []
    for f in findings:
        images, attachments = [], []
        for ev in sorted(f.evidence, key=lambda e: e.created_at):
            item = {"filename": ev.filename, "sha256": ev.sha256, "size": ev.size,
                    "description": ev.description, "content_type": ev.content_type}
            if (embed_images and ev.content_type in storage.INLINE_IMAGE_TYPES
                    and ev.size <= MAX_EMBED_BYTES):
                try:
                    data = storage.read_evidence(ev)
                    item["data_uri"] = f"data:{ev.content_type};base64,{base64.b64encode(data).decode()}"
                    images.append(item)
                    continue
                except FileNotFoundError:
                    pass
            attachments.append(item)
        finding_rows.append({
            "id": f.id,
            "ref": finding_ref(eng, f),
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "cvss_vector": f.cvss_vector,
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
        "team": [
            {"name": m.user.full_name, "email": m.user.email, "role": m.role}
            for m in sorted(eng.members, key=lambda m: (m.role != "lead", m.user.full_name))
        ],
        "scope": {
            "include": [{"kind": s.kind, "value": s.value, "notes": s.notes}
                        for s in eng.scope_items if s.rule == "include"],
            "exclude": [{"kind": s.kind, "value": s.value, "notes": s.notes}
                        for s in eng.scope_items if s.rule == "exclude"],
        },
        "severity_counts": {s: severity_counts.get(s, 0) for s in SEVERITIES},
        "total_findings": len(findings),
        "findings": finding_rows,
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
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "generated_by": user.full_name,
        "draft": include_drafts or eng.status not in ("delivered", "closed"),
    }


def render_html(context: dict) -> str:
    return _html_env.get_template("report.html.j2").render(**context)


def render_markdown(context: dict) -> str:
    return _md_env.get_template("report.md.j2").render(**context)

"""Findings exports for ticketing and vulnerability-management tools.

* CSV that Jira's CSV importer maps directly (Summary, Description, Priority,
  Labels) plus OffsecHub's own columns. Every cell that a spreadsheet could
  read as a formula is defused (OWASP "CSV injection"): findings routinely
  quote text a target controls.
* SARIF 2.1.0, for code-scanning dashboards and tooling that speaks it.
* DefectDojo's "Generic Findings Import" JSON.

Nothing here touches the network; the files are downloaded by the tester.
"""

import csv
import io
import json
import re

from .. import __version__
from ..models import Engagement, Finding
from ..schemas import REPORTABLE_STATUSES, SEVERITY_ORDER
from .cvss import version_of
from .findings import finding_ref

JIRA_PRIORITY = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
DOJO_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def select_findings(eng: Engagement, include_drafts: bool = False) -> list[Finding]:
    statuses = set(REPORTABLE_STATUSES) | ({"draft"} if include_drafts else set())
    return sorted((f for f in eng.findings if f.status in statuses),
                  key=lambda f: (SEVERITY_ORDER[f.severity], -(f.cvss_score or 0), f.number))


def _sections(f: Finding) -> str:
    parts = [(title, getattr(f, key)) for title, key in (
        ("Description", "description"), ("Impact", "impact"),
        ("Steps to reproduce", "steps_to_reproduce"), ("Remediation", "remediation"))]
    return "\n\n".join(f"{title}:\n{text.strip()}" for title, text in parts if text and text.strip())


def _cwe_number(cwe: str) -> int | None:
    m = re.search(r"(\d+)", cwe or "")
    return int(m.group(1)) if m else None


def _refs(f: Finding) -> list[str]:
    return [r.strip() for r in f.references.splitlines() if r.strip()]


def defuse(value: object) -> str:
    """A cell a spreadsheet will show as text, never evaluate."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def to_csv(eng: Engagement, findings: list[Finding]) -> str:
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writerow(["Summary", "Description", "Priority", "Labels", "Labels", "Finding ID", "Severity",
                "CVSS score", "CVSS vector", "CWE", "Status", "Retest", "Affected assets", "References"])
    for f in findings:
        ref = finding_ref(eng, f)
        w.writerow([defuse(v) for v in (
            f"{ref} {f.title}", _sections(f), JIRA_PRIORITY[f.severity], "pentest", eng.code, ref,
            f.severity, "" if f.cvss_score is None else f"{f.cvss_score:.1f}", f.cvss_vector, f.cwe,
            f.status, f.retests[-1].result if f.retests else "",
            "\n".join(t.value for t in f.targets), "\n".join(_refs(f)),
        )])
    return out.getvalue()


def to_sarif(eng: Engagement, findings: list[Finding]) -> str:
    rules, results = [], []
    for f in findings:
        ref = finding_ref(eng, f)
        props: dict = {"tags": ["security", "pentest", *([f.cwe] if f.cwe else [])], "severity": f.severity}
        if f.cvss_score is not None:
            # GitHub code scanning reads this to rank results.
            props["security-severity"] = f"{f.cvss_score:.1f}"
        rules.append({
            "id": ref,
            "name": re.sub(r"\W+", "", f.title.title())[:100] or ref,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": (f.description or f.title).strip()},
            "help": {"text": (f.remediation or "No remediation recorded.").strip(),
                     "markdown": (f.remediation or "No remediation recorded.").strip()},
            "helpUri": _refs(f)[0] if _refs(f) and _URL.match(_refs(f)[0]) else None,
            "properties": props,
        })
        results.append({
            "ruleId": ref,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}. {(f.impact or f.description or '').strip()}".strip()},
            "locations": [{"logicalLocations": [{"name": t.value, "fullyQualifiedName": t.value, "kind": "resource"}]}
                          for t in f.targets],
            "properties": {"status": f.status, "cvssVector": f.cvss_vector,
                           "retest": f.retests[-1].result if f.retests else None},
        })
    for r in rules:
        if r["helpUri"] is None:
            del r["helpUri"]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "OffsecHub", "version": __version__,
                                "informationUri": "https://github.com/ajfan6T/offsechub", "rules": rules}},
            "automationDetails": {"id": f"offsechub/{eng.code}/"},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def to_defectdojo(eng: Engagement, findings: list[Finding]) -> str:
    items = []
    for f in findings:
        ref = finding_ref(eng, f)
        item: dict = {
            "title": f.title,
            "severity": DOJO_SEVERITY[f.severity],
            "description": f.description or f.title,
            "mitigation": f.remediation,
            "impact": f.impact,
            "steps_to_reproduce": f.steps_to_reproduce,
            "references": "\n".join(_refs(f)),
            "unique_id_from_tool": ref,
            "vuln_id_from_tool": ref,
            "active": f.status not in ("remediated", "risk_accepted", "false_positive"),
            "verified": f.status != "draft",
            "is_mitigated": f.status == "remediated",
            "date": f.created_at.date().isoformat(),
            "endpoints": [t.value if _URL.match(t.value) else {"host": t.value} for t in f.targets],
        }
        if (cwe := _cwe_number(f.cwe)) is not None:
            item["cwe"] = cwe
        if f.cvss_vector and version_of(f.cvss_vector).startswith("3"):
            item["cvssv3"] = f.cvss_vector
            item["cvssv3_score"] = f.cvss_score
        elif f.cvss_vector:
            # DefectDojo's generic format has no CVSS 4.0 field: keep it visible.
            item["description"] = f"{item['description']}\n\n{f.cvss_vector} (score {f.cvss_score})"
        items.append(item)
    return json.dumps({"findings": items}, indent=2, ensure_ascii=False)


FORMATS = {
    "csv": (to_csv, "text/csv; charset=utf-8", "findings.csv"),
    "sarif": (to_sarif, "application/sarif+json", "findings.sarif"),
    "defectdojo": (to_defectdojo, "application/json", "defectdojo.json"),
}

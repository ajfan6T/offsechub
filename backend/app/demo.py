"""A realistic demo engagement, for trying the app and for screenshots.

It is built through the same vault paths as real work (encrypted blobs, the
importers, the scope guard), so the demo exercises what it shows.
"""

import sys
from collections.abc import Callable
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .bootstrap import get_setting, set_setting
from .models import (
    Client,
    Engagement,
    Finding,
    FindingTemplate,
    OperatorLogEntry,
    ReconImport,
    ScopeItem,
    TestCase,
)
from .services import audit, storage
from .services.findings import apply_cvss, next_finding_number
from .services.importers.apply import ImportContext, apply_result
from .services.importers.parsers import PARSERS
from .services.methodologies import load_methodologies
from .services.scope import normalize_scope_value
from .vault.manager import OpenVault

DEMO_CODE = "ACME-EXT-26"
DEMO_PROFILE = {
    "name": "Riley Chen",
    "organization": "Example Security Ltd",
    "email": "riley@example-security.test",
}
SAMPLE_IMPORTS = [("nmap", "nmap-acme.xml"), ("nuclei", "nuclei-acme.jsonl"),
                  ("list", "subdomains-acme.txt")]
GIT_CONFIG_RESPONSE = (
    b"GET /.git/config HTTP/1.1\r\nHost: www.acme-corp.example\r\n\r\n"
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/plain\r\n\r\n"
    b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
    b"\turl = git@git.acme-corp.example:web/www.git\n"
)

Store = Callable[[bytes], storage.StoredBlob]


def samples_dir() -> Path:
    """Sample tool output: bundled under ``sys._MEIPASS`` by PyInstaller, else the repo's samples/."""
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        return Path(bundle) / "samples"
    return Path(__file__).resolve().parents[2] / "samples"


def seed_demo(vault: OpenVault) -> None:
    """Add the demo engagement to an unlocked vault. Idempotent.

    Sets the operator profile only if none is set, so a real profile survives.
    """
    written: list[storage.StoredBlob] = []

    def store(data: bytes) -> storage.StoredBlob:
        blob = storage.write_bytes(vault, data)
        written.append(blob)
        return blob

    with vault.session() as db:
        if db.scalar(select(Engagement.id).where(Engagement.code == DEMO_CODE)) is not None:
            return
        try:
            _populate(db, store)
            db.commit()
        except BaseException:
            db.rollback()
            storage.delete_blobs(vault, [b.blob_id for b in written])
            raise


def _populate(db: Session, store: Store) -> None:
    if not any((get_setting(db, "operator.profile") or {}).values()):
        set_setting(db, "operator.profile", DEMO_PROFILE)
    eng = _engagement(db)
    _imports(db, eng, store)
    _findings(db, eng, store)
    _test_cases(db, eng)
    _oplog(db, eng)
    audit.record(db, action="create", entity_type="engagement", entity_id=eng.id,
                 engagement_id=eng.id, summary=f"Loaded demo engagement {eng.code}")


def _engagement(db: Session) -> Engagement:
    client = Client(name="ACME Corporation", industry="Manufacturing",
                    contact_name="Pat Morgan", contact_email="security@acme-corp.example")
    today = date.today()
    eng = Engagement(
        client=client,
        name="External Penetration Test 2026",
        code=DEMO_CODE,
        type="external_network",
        status="active",
        start_date=today - timedelta(days=5),
        end_date=today + timedelta(days=9),
        description="Annual external infrastructure and web perimeter assessment of ACME's "
                    "internet-facing estate.",
        rules_of_engagement=(
            "Testing window: Mon-Fri 08:00-18:00 UTC.\n"
            "No denial-of-service testing. Password spraying limited to 1 attempt per account "
            "per 30 minutes.\n"
            "Emergency contact: Pat Morgan, +1 555 0100.\n"
            "Source IPs: 192.0.2.200, 192.0.2.201."
        ),
        executive_summary=(
            "OffsecHub demo data. The assessment identified weaknesses in ACME's internet-facing "
            "web estate, most notably an exposed Git repository and remote access services "
            "reachable from the internet. None of the issues required advanced skill to discover."
        ),
    )
    db.add(eng)
    db.flush()
    for kind, value, rule, notes in [
        ("cidr", "203.0.113.0/28", "include", "Primary DMZ range"),
        ("wildcard", "*.acme-corp.example", "include", "All ACME subdomains"),
        ("domain", "acme-corp.example", "include", ""),
        ("domain", "vpn.acme-corp.example", "exclude", "Managed by third party; not authorised"),
        ("ip", "203.0.113.11", "exclude", "VPN concentrator (third party)"),
    ]:
        db.add(ScopeItem(engagement_id=eng.id, kind=kind, value=normalize_scope_value(kind, value),
                         rule=rule, notes=notes))
    db.flush()
    db.refresh(eng)
    return eng


def _imports(db: Session, eng: Engagement, store: Store) -> None:
    for tool, filename in SAMPLE_IMPORTS:
        data = (samples_dir() / filename).read_bytes()
        raw = storage.add_evidence(db, store(data), engagement_id=eng.id, filename=filename,
                                   content_type=None, description=f"Raw {tool} output (import)")
        stats = apply_result(ImportContext(db, eng, tool, True), PARSERS[tool](data))
        db.add(ReconImport(engagement_id=eng.id, tool=tool, filename=filename,
                           evidence_id=raw.id, stats=stats))
    db.flush()


def _findings(db: Session, eng: Engagement, store: Store) -> None:
    # Promote the nuclei .git finding and add two manual findings from the library.
    git = db.scalar(select(Finding).where(Finding.engagement_id == eng.id,
                                          Finding.source_ref == "nuclei:git-config"))
    if git:
        git.status = "confirmed"
        git.title = "Exposed Git Repository"
        git.impact = ("An attacker can download the repository history, which may contain "
                      "source code, credentials and internal hostnames.")
        git.remediation = ("Block access to /.git/ at the web server and rotate any secrets "
                           "committed to the repository.")
    targets = {t.value: t for t in eng.targets}
    rdp = {
        "title": "Internet-exposed RDP with weak administrator password",
        "steps_to_reproduce": "1. Connect to 203.0.113.12:3389\n2. Authenticate as "
                              "ACME\\Administrator with the password Winter2026!",
    }
    for template_title, target_values, status, overrides in [
        ("Weak TLS Configuration", ["203.0.113.10"], "confirmed", {}),
        ("Default or Weak Credentials", ["203.0.113.12"], "draft", rdp),
    ]:
        tpl = db.scalar(select(FindingTemplate).where(FindingTemplate.title == template_title))
        if tpl is None:  # the library was edited: skip rather than invent a write-up
            continue
        fields = {k: getattr(tpl, k) for k in
                  ("title", "severity", "cwe", "description", "impact", "remediation", "references")}
        f = Finding(engagement_id=eng.id, number=next_finding_number(db, eng.id), status=status,
                    source="template", **{**fields, **overrides})
        apply_cvss(f, tpl.cvss_vector, None)
        f.targets = [targets[v] for v in target_values if v in targets]
        db.add(f)
        db.flush()

    storage.add_evidence(
        db, store(GIT_CONFIG_RESPONSE), engagement_id=eng.id,
        filename="git-config-response.txt", content_type="text/plain",
        description="HTTP response showing the exposed Git config",
        finding_id=git.id if git else None,
    )


def _test_cases(db: Session, eng: Engagement) -> None:
    checklist = load_methodologies()["external-network"]
    progress = ["passed", "passed", "passed", "passed", "in_progress", "failed"]
    for i, case in enumerate(checklist["cases"]):
        db.add(TestCase(engagement_id=eng.id, methodology=checklist["id"], ref=case["ref"],
                        category=case["category"], title=case["title"],
                        description=case.get("description", ""),
                        status=progress[i] if i < len(progress) else "not_started"))


def _oplog(db: Session, eng: Engagement) -> None:
    now = datetime.now(timezone.utc)
    for delta, tool, target, command, desc, outcome in [
        (timedelta(days=4, hours=2), "nmap", "203.0.113.0/28",
         "nmap -sV -O -oX nmap-acme.xml 203.0.113.0/28", "Full TCP service scan of DMZ range",
         "success"),
        (timedelta(days=3, hours=5), "nuclei", "*.acme-corp.example",
         "nuclei -l hosts.txt -jsonl -o nuclei-acme.jsonl", "Automated web vulnerability scan",
         "success"),
        (timedelta(days=2, hours=1), "curl", "https://www.acme-corp.example/.git/config",
         "curl -s https://www.acme-corp.example/.git/config", "Validated .git exposure", "success"),
        (timedelta(hours=20), "netexec", "203.0.113.12",
         "nxc rdp 203.0.113.12 -u Administrator -p passwords.txt",
         "Password spray against RDP (3 attempts)", "detected"),
    ]:
        db.add(OperatorLogEntry(engagement_id=eng.id, operator=DEMO_PROFILE["name"],
                                occurred_at=now - delta, source_host="192.0.2.200", target=target,
                                tool=tool, command=command, description=desc, outcome=outcome))

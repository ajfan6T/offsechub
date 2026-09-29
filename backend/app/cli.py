"""Admin CLI.

    python -m app.cli create-user EMAIL "Full Name" --role lead
    python -m app.cli seed-demo
"""

import argparse
import getpass
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from . import db as db_module
from .bootstrap import bootstrap
from .models import (
    Client,
    Engagement,
    EngagementMember,
    Finding,
    FindingTemplate,
    OperatorLogEntry,
    ReconImport,
    ScopeItem,
    TestCase,
    User,
)
from .schemas import UserCreate
from .security import hash_password
from .services import storage
from .services.findings import apply_cvss, next_finding_number
from .services.importers.apply import ImportContext, apply_result
from .services.importers.parsers import PARSERS
from .services.methodologies import load_methodologies
from .services.scope import normalize_scope_value

SAMPLES = Path(__file__).resolve().parent.parent.parent / "samples"
DEMO_PASSWORD = "offsechub-demo-password"


def create_user(args) -> int:
    password = args.password or getpass.getpass("Password (min 12 chars): ")
    try:
        body = UserCreate(email=args.email, full_name=args.full_name, password=password, role=args.role)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    bootstrap()
    with db_module.SessionLocal() as db:
        if db.scalar(select(User).where(User.email == body.email)):
            print(f"User {body.email} already exists", file=sys.stderr)
            return 1
        db.add(User(email=body.email, full_name=body.full_name, role=body.role,
                    password_hash=hash_password(body.password)))
        db.commit()
    print(f"Created {body.role} {body.email}")
    return 0


def _user(db, email: str, name: str, role: str) -> User:
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(email=email, full_name=name, role=role, password_hash=hash_password(DEMO_PASSWORD))
        db.add(user)
        db.flush()
    return user


def seed_demo(_args) -> int:
    bootstrap()
    with db_module.SessionLocal() as db:
        if db.scalar(select(Engagement).where(Engagement.code == "ACME-EXT-26")):
            print("Demo data already present")
            return 0
        lead = _user(db, "lead@offsechub.local", "Riley Chen", "lead")
        tester = _user(db, "tester@offsechub.local", "Sam Okafor", "tester")
        viewer = _user(db, "viewer@offsechub.local", "Jordan Blake", "viewer")

        client = Client(name="ACME Corporation", industry="Manufacturing",
                        contact_name="Pat Morgan", contact_email="security@acme-corp.example")
        db.add(client)
        db.flush()

        today = date.today()
        eng = Engagement(
            client_id=client.id,
            name="External Penetration Test 2026",
            code="ACME-EXT-26",
            type="external_network",
            status="active",
            start_date=today - timedelta(days=5),
            end_date=today + timedelta(days=9),
            description="Annual external infrastructure and web perimeter assessment of ACME's internet-facing estate.",
            rules_of_engagement=(
                "Testing window: Mon-Fri 08:00-18:00 UTC.\n"
                "No denial-of-service testing. Password spraying limited to 1 attempt per account per 30 minutes.\n"
                "Emergency contact: Pat Morgan, +1 555 0100.\n"
                "Source IPs: 192.0.2.200, 192.0.2.201."
            ),
            executive_summary=(
                "OffsecHub demo data. The assessment identified weaknesses in ACME's internet-facing web "
                "estate, most notably an exposed Git repository and remote access services reachable from "
                "the internet. None of the issues required advanced skill to discover."
            ),
            created_by_id=lead.id,
        )
        eng.members = [
            EngagementMember(user_id=lead.id, role="lead"),
            EngagementMember(user_id=tester.id, role="tester"),
            EngagementMember(user_id=viewer.id, role="viewer"),
        ]
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

        for tool, fname in [("nmap", "nmap-acme.xml"), ("nuclei", "nuclei-acme.jsonl"),
                            ("list", "subdomains-acme.txt")]:
            data = (SAMPLES / fname).read_bytes()
            raw = storage.store_evidence(db, engagement_id=eng.id, filename=fname, data=data,
                                         content_type=None, uploaded_by_id=tester.id,
                                         description=f"Raw {tool} output (import)")
            stats = apply_result(ImportContext(db, eng, tool, tester.id, True), PARSERS[tool](data))
            db.add(ReconImport(engagement_id=eng.id, tool=tool, filename=fname, evidence_id=raw.id,
                               stats=stats, created_by_id=tester.id))
        db.flush()

        # Promote the nuclei .git finding and add two manual findings from the library.
        git = db.scalar(select(Finding).where(Finding.engagement_id == eng.id,
                                              Finding.source_ref == "nuclei:git-config"))
        if git:
            git.status = "confirmed"
            git.title = "Exposed Git Repository"
            git.impact = ("An attacker can download the repository history, which may contain source code, "
                          "credentials and internal hostnames.")
            git.remediation = "Block access to /.git/ at the web server and rotate any secrets committed to the repository."
        targets = {t.value: t for t in eng.targets}
        for title, target_values, status in [
            ("Weak TLS Configuration", ["203.0.113.10"], "confirmed"),
            ("Default or Weak Credentials", ["203.0.113.12"], "draft"),
        ]:
            tpl = db.scalar(select(FindingTemplate).where(FindingTemplate.title == title))
            f = Finding(engagement_id=eng.id, number=next_finding_number(db, eng.id), title=tpl.title,
                        status=status, cwe=tpl.cwe, description=tpl.description, impact=tpl.impact,
                        remediation=tpl.remediation, references=tpl.references, source="template",
                        created_by_id=tester.id, severity=tpl.severity)
            apply_cvss(f, tpl.cvss_vector, None)
            f.targets = [targets[v] for v in target_values if v in targets]
            db.add(f)
            db.flush()
        rdp = db.scalar(select(Finding).where(Finding.engagement_id == eng.id,
                                              Finding.title == "Default or Weak Credentials"))
        rdp.title = "Internet-exposed RDP with weak administrator password"
        rdp.steps_to_reproduce = "1. Connect to 203.0.113.12:3389\n2. Authenticate as ACME\\Administrator with the password Winter2026!"

        storage.store_evidence(
            db, engagement_id=eng.id, filename="git-config-response.txt",
            data=(b"GET /.git/config HTTP/1.1\r\nHost: www.acme-corp.example\r\n\r\n"
                  b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/plain\r\n\r\n"
                  b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
                  b"\turl = git@git.acme-corp.example:web/www.git\n"),
            content_type="text/plain", uploaded_by_id=tester.id,
            description="HTTP response showing the exposed Git config", finding_id=git.id if git else None,
        )

        checklist = load_methodologies()["external-network"]
        for i, case in enumerate(checklist["cases"]):
            db.add(TestCase(engagement_id=eng.id, methodology=checklist["id"], ref=case["ref"],
                            category=case["category"], title=case["title"],
                            description=case.get("description", ""),
                            status=["passed", "passed", "passed", "passed", "in_progress", "failed"][i]
                            if i < 6 else "not_started",
                            assignee_id=tester.id if i % 2 else lead.id))

        now = datetime.now(timezone.utc)
        for delta, tool, target, command, desc, outcome in [
            (timedelta(days=4, hours=2), "nmap", "203.0.113.0/28", "nmap -sV -O -oX nmap-acme.xml 203.0.113.0/28",
             "Full TCP service scan of DMZ range", "success"),
            (timedelta(days=3, hours=5), "nuclei", "*.acme-corp.example", "nuclei -l hosts.txt -jsonl -o nuclei-acme.jsonl",
             "Automated web vulnerability scan", "success"),
            (timedelta(days=2, hours=1), "curl", "https://www.acme-corp.example/.git/config",
             "curl -s https://www.acme-corp.example/.git/config", "Validated .git exposure", "success"),
            (timedelta(hours=20), "netexec", "203.0.113.12", "nxc rdp 203.0.113.12 -u Administrator -p passwords.txt",
             "Password spray against RDP (3 attempts)", "detected"),
        ]:
            db.add(OperatorLogEntry(engagement_id=eng.id, user_id=tester.id, occurred_at=now - delta,
                                    source_host="192.0.2.200", target=target, tool=tool, command=command,
                                    description=desc, outcome=outcome))
        db.commit()
    print("Seeded demo engagement ACME-EXT-26.")
    print(f"Demo users (password '{DEMO_PASSWORD}'): lead@offsechub.local, tester@offsechub.local, "
          "viewer@offsechub.local")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="offsechub")
    sub = parser.add_subparsers(dest="command", required=True)

    cu = sub.add_parser("create-user", help="create a user account")
    cu.add_argument("email")
    cu.add_argument("full_name")
    cu.add_argument("--role", default="tester", choices=["admin", "lead", "tester", "viewer"])
    cu.add_argument("--password", help="omit to be prompted")
    cu.set_defaults(func=create_user)

    sd = sub.add_parser("seed-demo", help="load a demo engagement with sample data")
    sd.set_defaults(func=seed_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""Merge parsed tool output into an engagement, enforcing scope."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import Engagement, Finding, Service, Target
from .. import cvss
from ..findings import next_finding_number
from ..scope import ScopeMatcher
from .parsers import ParsedHost, ParseResult


class ImportContext:
    def __init__(self, db: Session, engagement: Engagement, tool: str, user_id: int | None,
                 skip_out_of_scope: bool):
        self.db = db
        self.engagement = engagement
        self.tool = tool
        self.user_id = user_id
        self.skip_out_of_scope = skip_out_of_scope
        self.matcher = ScopeMatcher(engagement.scope_items)
        self.targets: dict[str, Target] = {
            t.value: t for t in db.scalars(select(Target).where(Target.engagement_id == engagement.id))
        }
        self.stats = {
            "hosts_seen": 0,
            "targets_created": 0,
            "targets_updated": 0,
            "services_created": 0,
            "findings_created": 0,
            "findings_updated": 0,
            "skipped_out_of_scope": 0,
            "skipped_excluded": 0,
            "errors": [],
        }
        self._skipped: set[str] = set()

    def target_for(self, host: ParsedHost) -> Target | None:
        if host.value in self._skipped:
            return None
        status = self.matcher.check_target(host.value, host.ip, host.hostname)
        # Explicit exclusions are never imported; out-of-scope is configurable.
        if status == "excluded" or (status == "out_of_scope" and self.skip_out_of_scope):
            self._skipped.add(host.value)
            key = "skipped_excluded" if status == "excluded" else "skipped_out_of_scope"
            self.stats[key] += 1
            return None

        target = self.targets.get(host.value)
        if target is None:
            target = Target(
                engagement_id=self.engagement.id,
                kind=host.kind,
                value=host.value,
                ip=host.ip,
                hostname=host.hostname,
                os=host.os,
                source=self.tool,
                tags=[],
                services=[],
            )
            self.db.add(target)
            self.targets[host.value] = target
            self.stats["targets_created"] += 1
        else:
            changed = False
            for attr in ("ip", "hostname", "os"):
                new = getattr(host, attr)
                if new and not getattr(target, attr):
                    setattr(target, attr, new)
                    changed = True
            if changed:
                self.stats["targets_updated"] += 1
        return target

    def merge_services(self, target: Target, host: ParsedHost) -> None:
        existing = {(s.port, s.protocol): s for s in target.services}
        for ps in host.services:
            svc = existing.get((ps.port, ps.protocol))
            if svc is None:
                svc = Service(port=ps.port, protocol=ps.protocol)
                target.services.append(svc)
                existing[(ps.port, ps.protocol)] = svc
                self.stats["services_created"] += 1
            svc.state = ps.state
            # Keep manual enrichment unless the scan has something newer.
            for attr in ("name", "product", "version", "extra_info"):
                val = getattr(ps, attr)
                if val:
                    setattr(svc, attr, val)


def apply_result(ctx: ImportContext, parsed: ParseResult) -> dict:
    db = ctx.db
    ctx.stats["errors"] = parsed.errors[:50]

    seen_hosts: set[str] = set()
    for host in parsed.hosts:
        if host.value not in seen_hosts:
            seen_hosts.add(host.value)
            ctx.stats["hosts_seen"] += 1
        target = ctx.target_for(host)
        if target is not None and host.services:
            ctx.merge_services(target, host)

    if parsed.issues:
        db.flush()
        existing = {
            f.source_ref: f
            for f in db.scalars(
                select(Finding).where(
                    Finding.engagement_id == ctx.engagement.id, Finding.source_ref != ""
                )
            )
        }
        number = next_finding_number(db, ctx.engagement.id)
        for issue in parsed.issues:
            target = ctx.target_for(issue.host)
            if target is None:
                continue
            finding = existing.get(issue.key)
            if finding is None:
                finding = Finding(
                    engagement_id=ctx.engagement.id,
                    number=number,
                    title=issue.title[:255],
                    severity=issue.severity,
                    status="draft",
                    description=issue.description,
                    remediation=issue.remediation,
                    references="\n".join(dict.fromkeys(issue.references)),
                    cwe=issue.cwe[:20],
                    steps_to_reproduce=issue.reproduction,
                    source=ctx.tool,
                    source_ref=issue.key,
                    created_by_id=ctx.user_id,
                    targets=[],
                )
                if issue.cvss_vector:
                    try:
                        res = cvss.calculate(issue.cvss_vector)
                        finding.cvss_vector, finding.cvss_score = res.vector, res.score
                    except cvss.CvssError:
                        pass
                db.add(finding)
                existing[issue.key] = finding
                number += 1
                ctx.stats["findings_created"] += 1
            else:
                # Same check on another host/URL: add the instance, don't duplicate the finding.
                if issue.matched_at and issue.matched_at not in finding.steps_to_reproduce:
                    finding.steps_to_reproduce = (
                        finding.steps_to_reproduce + "\n\n" + issue.reproduction
                    ).strip()
                    ctx.stats["findings_updated"] += 1
            if target not in finding.targets:
                finding.targets.append(target)
    db.flush()
    return ctx.stats

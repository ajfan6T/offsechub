"""Database models.

Single-operator schema, stored in the vault's in-memory SQLite database.
Enumerated fields are plain strings; the allowed values live in
``app.schemas`` (as ``Literal`` types) so the API validates them.
"""

from datetime import date, datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )






class Setting(Base):
    """Key/value settings stored inside the encrypted vault (operator profile, auto-lock)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict | list | str | int | bool | None] = mapped_column(JSON)


class Client(TimestampMixin, Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    industry: Mapped[str] = mapped_column(String(100), default="")
    contact_name: Mapped[str] = mapped_column(String(255), default="")
    contact_email: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")

    engagements: Mapped[list["Engagement"]] = relationship(back_populates="client")


class Engagement(TimestampMixin, Base):
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    code: Mapped[str] = mapped_column(String(32), unique=True)
    type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(20), default="planning")
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    description: Mapped[str] = mapped_column(Text, default="")
    rules_of_engagement: Mapped[str] = mapped_column(Text, default="")
    executive_summary: Mapped[str] = mapped_column(Text, default="")

    client: Mapped[Client] = relationship(back_populates="engagements")
    scope_items: Mapped[list["ScopeItem"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    targets: Mapped[list["Target"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    test_cases: Mapped[list["TestCase"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    imports: Mapped[list["ReconImport"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    oplog: Mapped[list["OperatorLogEntry"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )




class ScopeItem(Base):
    __tablename__ = "scope_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(20))  # ip | cidr | range | domain | wildcard | url | other
    value: Mapped[str] = mapped_column(String(512))
    rule: Mapped[str] = mapped_column(String(10), default="include")  # include | exclude
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="scope_items")


finding_targets = Table(
    "finding_targets",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
    Column("target_id", ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True),
)


class Target(TimestampMixin, Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("engagement_id", "value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(20), default="host")
    value: Mapped[str] = mapped_column(String(512))
    hostname: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    os: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(20), default="new")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(50), default="manual")

    engagement: Mapped[Engagement] = relationship(back_populates="targets")
    services: Mapped[list["Service"]] = relationship(
        back_populates="target", cascade="all, delete-orphan", order_by="Service.port"
    )
    findings: Mapped[list["Finding"]] = relationship(
        secondary=finding_targets, back_populates="targets"
    )


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("target_id", "port", "protocol"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20), default="open")
    name: Mapped[str] = mapped_column(String(100), default="")
    product: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(255), default="")
    extra_info: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    target: Mapped[Target] = relationship(back_populates="services")


class ReconImport(Base):
    __tablename__ = "recon_imports"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    tool: Mapped[str] = mapped_column(String(30))
    filename: Mapped[str] = mapped_column(String(255))
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"))
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="imports")


class TestCase(TimestampMixin, Base):
    __tablename__ = "test_cases"
    __test__ = False  # keep pytest from collecting this class

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    methodology: Mapped[str] = mapped_column(String(100), default="custom")
    ref: Mapped[str] = mapped_column(String(50), default="")
    category: Mapped[str] = mapped_column(String(100), default="General")
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="not_started")
    notes: Mapped[str] = mapped_column(Text, default="")
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))

    engagement: Mapped[Engagement] = relationship(back_populates="test_cases")


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("engagement_id", "number"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    number: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="draft")
    cvss_vector: Mapped[str] = mapped_column(String(128), default="")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cwe: Mapped[str] = mapped_column(String(20), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    steps_to_reproduce: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(50), default="manual")
    source_ref: Mapped[str] = mapped_column(String(512), default="")

    engagement: Mapped[Engagement] = relationship(back_populates="findings")
    targets: Mapped[list[Target]] = relationship(
        secondary=finding_targets, back_populates="findings", order_by="Target.value"
    )
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="finding")


class FindingTemplate(TimestampMixin, Base):
    """Reusable write-ups (the finding library)."""

    __tablename__ = "finding_templates"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), unique=True)
    category: Mapped[str] = mapped_column(String(100), default="General")
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    cvss_vector: Mapped[str] = mapped_column(String(128), default="")
    cwe: Mapped[str] = mapped_column(String(20), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(100))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    storage_key: Mapped[str] = mapped_column(String(255), unique=True)  # blob id in the vault
    # Random per-blob AES key. It exists only here (inside the encrypted DB), so
    # deleting the row cryptographically erases the evidence file.
    blob_key: Mapped[bytes] = mapped_column(LargeBinary(32))
    description: Mapped[str] = mapped_column(Text, default="")
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"))
    test_case_id: Mapped[int | None] = mapped_column(
        ForeignKey("test_cases.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="evidence")
    finding: Mapped[Finding | None] = relationship(back_populates="evidence")


class OperatorLogEntry(Base):
    """What a tester did, from where, against what, and when (deconfliction record)."""

    __tablename__ = "operator_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    operator: Mapped[str] = mapped_column(String(255), default="")
    source_host: Mapped[str] = mapped_column(String(255), default="")
    target: Mapped[str] = mapped_column(String(512), default="")
    tool: Mapped[str] = mapped_column(String(100), default="")
    command: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    outcome: Mapped[str] = mapped_column(String(20), default="info")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="oplog")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    # SET NULL so the audit trail outlives a deleted engagement.
    engagement_id: Mapped[int | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(20))  # create | update | delete | login | import | export
    entity_type: Mapped[str] = mapped_column(String(50))
    entity_id: Mapped[int | None] = mapped_column(Integer)
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


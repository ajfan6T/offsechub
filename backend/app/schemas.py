"""API request and response models (single operator: no user references)."""

import re
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

EngagementType = Literal[
    "external_network",
    "internal_network",
    "web_application",
    "api",
    "mobile",
    "cloud",
    "wireless",
    "social_engineering",
    "red_team",
    "physical",
    "other",
]
EngagementStatus = Literal["planning", "active", "reporting", "review", "delivered", "closed"]
ScopeKind = Literal["ip", "cidr", "range", "domain", "wildcard", "url", "other"]
ScopeRule = Literal["include", "exclude"]
ScopeStatus = Literal["in_scope", "out_of_scope", "excluded"]
TargetKind = Literal["host", "domain", "web", "api", "network", "cloud", "mobile", "other"]
TargetStatus = Literal["new", "in_progress", "tested", "compromised"]
TestStatus = Literal["not_started", "in_progress", "passed", "failed", "not_applicable", "blocked"]
Severity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal[
    "draft", "confirmed", "reported", "remediated", "risk_accepted", "false_positive"
]
OplogOutcome = Literal["info", "success", "failure", "detected"]
ImportTool = Literal["nmap", "nuclei", "list"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Findings in these states appear in client-facing reports.
REPORTABLE_STATUSES = ("confirmed", "reported", "remediated", "risk_accepted")

_CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{1,31}$")


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------------- clients


class ClientIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    industry: str = ""
    contact_name: str = ""
    contact_email: str = ""
    notes: str = ""


class ClientUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    industry: str | None = None
    contact_name: str | None = None
    contact_email: str | None = None
    notes: str | None = None


class ClientBrief(ORM):
    id: int
    name: str


class ClientOut(ORM):
    id: int
    name: str
    industry: str
    contact_name: str
    contact_email: str
    notes: str
    created_at: datetime
    engagement_count: int = 0


# ---------------------------------------------------------------- engagements


class EngagementCreate(BaseModel):
    client_id: int
    name: str = Field(min_length=1, max_length=255)
    code: str
    type: EngagementType
    status: EngagementStatus = "planning"
    start_date: date | None = None
    end_date: date | None = None
    description: str = ""
    rules_of_engagement: str = ""

    @field_validator("code")
    @classmethod
    def _code(cls, v: str) -> str:
        v = v.strip().upper()
        if not _CODE_RE.match(v):
            raise ValueError("code must be 2-32 chars of A-Z, 0-9 and '-'")
        return v


class EngagementUpdate(BaseModel):
    client_id: int | None = None
    name: str | None = Field(default=None, min_length=1, max_length=255)
    type: EngagementType | None = None
    status: EngagementStatus | None = None
    start_date: date | None = None
    end_date: date | None = None
    description: str | None = None
    rules_of_engagement: str | None = None
    executive_summary: str | None = None


class EngagementOut(ORM):
    id: int
    client: ClientBrief
    name: str
    code: str
    type: EngagementType
    status: EngagementStatus
    start_date: date | None
    end_date: date | None
    description: str
    rules_of_engagement: str
    executive_summary: str
    created_at: datetime
    updated_at: datetime
    finding_counts: dict[str, int] = {}


class EngagementSummary(BaseModel):
    targets: int
    targets_in_scope: int
    targets_out_of_scope: int
    targets_compromised: int
    services: int
    scope_items: int
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]
    tests_by_status: dict[str, int]
    evidence: int
    oplog_entries: int


# ---------------------------------------------------------------------- scope


class ScopeItemIn(BaseModel):
    kind: ScopeKind
    value: str = Field(min_length=1, max_length=512)
    rule: ScopeRule = "include"
    notes: str = ""


class ScopeItemUpdate(BaseModel):
    rule: ScopeRule | None = None
    notes: str | None = None


class ScopeItemOut(ORM):
    id: int
    kind: ScopeKind
    value: str
    rule: ScopeRule
    notes: str
    created_at: datetime


class ScopeCheckIn(BaseModel):
    values: list[str] = Field(min_length=1, max_length=1000)


class ScopeCheckResult(BaseModel):
    value: str
    status: ScopeStatus
    rule_id: int | None
    reason: str


# -------------------------------------------------------------------- targets


class ServiceIn(BaseModel):
    port: int = Field(ge=0, le=65535)
    protocol: Literal["tcp", "udp", "sctp"] = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""


class ServiceOut(ORM):
    id: int
    port: int
    protocol: str
    state: str
    name: str
    product: str
    version: str
    extra_info: str


class TargetIn(BaseModel):
    kind: TargetKind = "host"
    value: str = Field(min_length=1, max_length=512)
    hostname: str = ""
    ip: str = ""
    os: str = ""
    status: TargetStatus = "new"
    tags: list[str] = []
    notes: str = ""


class TargetUpdate(BaseModel):
    kind: TargetKind | None = None
    hostname: str | None = None
    ip: str | None = None
    os: str | None = None
    status: TargetStatus | None = None
    tags: list[str] | None = None
    notes: str | None = None


class TargetBrief(ORM):
    id: int
    value: str
    kind: str


class TargetOut(ORM):
    id: int
    kind: TargetKind
    value: str
    hostname: str
    ip: str
    os: str
    status: TargetStatus
    tags: list[str]
    notes: str
    source: str
    created_at: datetime
    updated_at: datetime
    services: list[ServiceOut]
    scope_status: ScopeStatus = "out_of_scope"
    finding_count: int = 0


# ---------------------------------------------------------------------- recon


class ImportOut(ORM):
    id: int
    tool: str
    filename: str
    evidence_id: int | None
    stats: dict
    created_at: datetime


# -------------------------------------------------------------------- testing


class MethodologyOut(BaseModel):
    id: str
    name: str
    description: str
    case_count: int
    categories: list[str]


class ApplyMethodologyIn(BaseModel):
    methodology_id: str
    target_id: int | None = None


class TestCaseIn(BaseModel):
    methodology: str = "custom"
    ref: str = ""
    category: str = "General"
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    status: TestStatus = "not_started"
    notes: str = ""
    target_id: int | None = None
    finding_id: int | None = None


class TestCaseUpdate(BaseModel):
    category: str | None = None
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    status: TestStatus | None = None
    notes: str | None = None
    target_id: int | None = None
    finding_id: int | None = None


class TestCaseOut(ORM):
    id: int
    methodology: str
    ref: str
    category: str
    title: str
    description: str
    status: TestStatus
    notes: str
    target_id: int | None
    finding_id: int | None
    updated_at: datetime


# ------------------------------------------------------------------- evidence


class EvidenceOut(ORM):
    id: int
    filename: str
    content_type: str
    size: int
    sha256: str
    description: str
    finding_id: int | None
    target_id: int | None
    test_case_id: int | None
    created_at: datetime
    is_image: bool = False


class EvidenceUpdate(BaseModel):
    description: str | None = None
    finding_id: int | None = None
    target_id: int | None = None
    test_case_id: int | None = None


class EvidenceTextIn(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1)
    description: str = ""
    finding_id: int | None = None
    target_id: int | None = None
    test_case_id: int | None = None


# ------------------------------------------------------------------- findings


class FindingIn(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    severity: Severity | None = None
    status: FindingStatus = "draft"
    cvss_vector: str | None = None
    cwe: str | None = None
    description: str | None = None
    impact: str | None = None
    steps_to_reproduce: str = ""
    remediation: str | None = None
    references: str | None = None
    target_ids: list[int] = []
    template_id: int | None = None


class FindingUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    severity: Severity | None = None
    status: FindingStatus | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    description: str | None = None
    impact: str | None = None
    steps_to_reproduce: str | None = None
    remediation: str | None = None
    references: str | None = None
    target_ids: list[int] | None = None


class FindingOut(ORM):
    id: int
    number: int
    ref: str = ""
    title: str
    severity: Severity
    status: FindingStatus
    cvss_vector: str
    cvss_score: float | None
    cwe: str
    description: str
    impact: str
    steps_to_reproduce: str
    remediation: str
    references: str
    source: str
    targets: list[TargetBrief]
    evidence_count: int = 0
    created_at: datetime
    updated_at: datetime


class FindingTemplateIn(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    category: str = "General"
    severity: Severity = "medium"
    cvss_vector: str = ""
    cwe: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    references: str = ""


class FindingTemplateUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    category: str | None = None
    severity: Severity | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    description: str | None = None
    impact: str | None = None
    remediation: str | None = None
    references: str | None = None


class FindingTemplateOut(ORM):
    id: int
    title: str
    category: str
    severity: Severity
    cvss_vector: str
    cvss_score: float | None = None
    cwe: str
    description: str
    impact: str
    remediation: str
    references: str


class CvssIn(BaseModel):
    vector: str


class CvssOut(BaseModel):
    vector: str
    score: float
    severity: Severity
    metrics: dict[str, str]


# ---------------------------------------------------------- op log / activity


class OplogIn(BaseModel):
    occurred_at: datetime | None = None
    # Defaults to the profile name. Stored per entry, so an exported log stays
    # accurate after the profile changes (or when logging for a colleague).
    operator: str | None = Field(default=None, max_length=255)
    source_host: str = ""
    target: str = ""
    tool: str = ""
    command: str = ""
    description: str = ""
    outcome: OplogOutcome = "info"


class OplogOut(ORM):
    id: int
    occurred_at: datetime
    operator: str
    source_host: str
    target: str
    tool: str
    command: str
    description: str
    outcome: OplogOutcome
    created_at: datetime


class ActivityOut(ORM):
    id: int
    engagement_id: int | None
    action: str
    entity_type: str
    entity_id: int | None
    summary: str
    created_at: datetime


# ------------------------------------------------------------------ dashboard


class DashboardOut(BaseModel):
    engagements_by_status: dict[str, int]
    open_findings_by_severity: dict[str, int]
    open_tests: int  # not started, in progress or blocked, across active engagements
    active_engagements: list[EngagementOut]
    recent_findings: list[dict]

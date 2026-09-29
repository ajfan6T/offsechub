// Mirrors backend/app/schemas.py.

export type Role = "admin" | "lead" | "tester" | "viewer";
export type MemberRole = "lead" | "tester" | "viewer";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus =
  | "draft"
  | "confirmed"
  | "reported"
  | "remediated"
  | "risk_accepted"
  | "false_positive";
export type EngagementStatus = "planning" | "active" | "reporting" | "review" | "delivered" | "closed";
export type EngagementType =
  | "external_network"
  | "internal_network"
  | "web_application"
  | "api"
  | "mobile"
  | "cloud"
  | "wireless"
  | "social_engineering"
  | "red_team"
  | "physical"
  | "other";
export type ScopeKind = "ip" | "cidr" | "range" | "domain" | "wildcard" | "url" | "other";
export type ScopeStatus = "in_scope" | "out_of_scope" | "excluded";
export type TargetKind = "host" | "domain" | "web" | "api" | "network" | "cloud" | "mobile" | "other";
export type TargetStatus = "new" | "in_progress" | "tested" | "compromised";
export type TestStatus = "not_started" | "in_progress" | "passed" | "failed" | "not_applicable" | "blocked";
export type OplogOutcome = "info" | "success" | "failure" | "detected";

export interface UserBrief {
  id: number;
  full_name: string;
  email: string;
}

export interface User extends UserBrief {
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface ApiToken {
  id: number;
  name: string;
  kind: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  token?: string;
}

export interface Client {
  id: number;
  name: string;
  industry: string;
  contact_name: string;
  contact_email: string;
  notes: string;
  created_at: string;
  engagement_count: number;
}

export interface Engagement {
  id: number;
  client: { id: number; name: string };
  name: string;
  code: string;
  type: EngagementType;
  status: EngagementStatus;
  start_date: string | null;
  end_date: string | null;
  description: string;
  rules_of_engagement: string;
  executive_summary: string;
  created_at: string;
  updated_at: string;
  my_role: MemberRole | null;
  finding_counts: Partial<Record<Severity, number>>;
}

export interface Member {
  user: UserBrief;
  role: MemberRole;
  added_at: string;
}

export interface EngagementSummary {
  targets: number;
  targets_in_scope: number;
  targets_out_of_scope: number;
  targets_compromised: number;
  services: number;
  scope_items: number;
  findings_by_severity: Partial<Record<Severity, number>>;
  findings_by_status: Partial<Record<FindingStatus, number>>;
  tests_by_status: Partial<Record<TestStatus, number>>;
  evidence: number;
  oplog_entries: number;
}

export interface ScopeItem {
  id: number;
  kind: ScopeKind;
  value: string;
  rule: "include" | "exclude";
  notes: string;
  created_at: string;
}

export interface ScopeCheckResult {
  value: string;
  status: ScopeStatus;
  rule_id: number | null;
  reason: string;
}

export interface Service {
  id: number;
  port: number;
  protocol: string;
  state: string;
  name: string;
  product: string;
  version: string;
  extra_info: string;
}

export interface Target {
  id: number;
  kind: TargetKind;
  value: string;
  hostname: string;
  ip: string;
  os: string;
  status: TargetStatus;
  tags: string[];
  notes: string;
  source: string;
  created_at: string;
  updated_at: string;
  services: Service[];
  scope_status: ScopeStatus;
  finding_count: number;
}

export interface ReconImport {
  id: number;
  tool: string;
  filename: string;
  evidence_id: number | null;
  stats: {
    hosts_seen: number;
    targets_created: number;
    targets_updated: number;
    services_created: number;
    findings_created: number;
    findings_updated: number;
    skipped_out_of_scope: number;
    skipped_excluded: number;
    errors: string[];
  };
  created_at: string;
  created_by: UserBrief | null;
}

export interface Methodology {
  id: string;
  name: string;
  description: string;
  case_count: number;
  categories: string[];
}

export interface TestCase {
  id: number;
  methodology: string;
  ref: string;
  category: string;
  title: string;
  description: string;
  status: TestStatus;
  notes: string;
  assignee: UserBrief | null;
  target_id: number | null;
  finding_id: number | null;
  updated_at: string;
}

export interface Evidence {
  id: number;
  filename: string;
  content_type: string;
  size: number;
  sha256: string;
  description: string;
  finding_id: number | null;
  target_id: number | null;
  test_case_id: number | null;
  uploaded_by: UserBrief | null;
  created_at: string;
  is_image: boolean;
}

export interface Finding {
  id: number;
  number: number;
  ref: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  cvss_vector: string;
  cvss_score: number | null;
  cwe: string;
  description: string;
  impact: string;
  steps_to_reproduce: string;
  remediation: string;
  references: string;
  source: string;
  targets: { id: number; value: string; kind: string }[];
  evidence_count: number;
  created_by: UserBrief | null;
  created_at: string;
  updated_at: string;
}

export interface FindingTemplate {
  id: number;
  title: string;
  category: string;
  severity: Severity;
  cvss_vector: string;
  cvss_score: number | null;
  cwe: string;
  description: string;
  impact: string;
  remediation: string;
  references: string;
}

export interface CvssResult {
  vector: string;
  score: number;
  severity: Severity;
  metrics: Record<string, string>;
}

export interface OplogEntry {
  id: number;
  occurred_at: string;
  source_host: string;
  target: string;
  tool: string;
  command: string;
  description: string;
  outcome: OplogOutcome;
  user: UserBrief | null;
  created_at: string;
}

export interface AuditEvent {
  id: number;
  user: UserBrief | null;
  engagement_id: number | null;
  action: string;
  entity_type: string;
  entity_id: number | null;
  summary: string;
  ip_address: string;
  created_at: string;
}

export interface Dashboard {
  engagements_by_status: Partial<Record<EngagementStatus, number>>;
  open_findings_by_severity: Partial<Record<Severity, number>>;
  my_open_tests: number;
  active_engagements: Engagement[];
  recent_findings: {
    id: number;
    engagement_id: number;
    engagement_code: string;
    ref: string;
    title: string;
    severity: Severity;
    status: FindingStatus;
    created_at: string;
  }[];
}

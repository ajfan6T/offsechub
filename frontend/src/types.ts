// Mirrors backend/app/schemas.py and the vault/app endpoints in backend/app/api/vault.py.

// ------------------------------------------------------------- vault and app

export type VaultState = "none" | "locked" | "unlocked";

export interface VaultStatus {
  state: VaultState;
  path: string | null;
  name: string | null;
  /** 0 means auto-lock is off. */
  auto_lock_minutes: number;
  /** Null while locked or when auto-lock is off. */
  seconds_until_lock: number | null;
  /** Why the vault is locked: "manual", "idle" or "exit" (null while unlocked). */
  lock_reason: string | null;
  /** Unlocked with the recovery key: a new password must be chosen before anything else. */
  must_set_password: boolean;
  /** Integrity problems found on unlock (fell back to a backup, quarantined a file...). */
  warnings: string[];
  notices: string[];
  /** Changes not yet sealed to disk (saves are coalesced, so briefly true after edits). */
  dirty: boolean;
  last_saved_at: string | null;
  /** Last failed background save; cleared by the next successful one. */
  save_error: string | null;
}

export interface AppInfo {
  version: string;
  /** Running inside the native desktop shell (vs. --browser mode). */
  desktop: boolean;
  platform: string;
  default_vault_dir: string;
}

export interface RecentVault {
  path: string;
  name: string;
  exists: boolean;
}

export interface RecentVaults {
  remember_recent: boolean;
  vaults: RecentVault[];
}

/** Operator profile, stored inside the vault; used on reports and in the op log. */
export interface Profile {
  name: string;
  email: string;
  organization: string;
}

/**
 * The recovery keyslot on its own (no secret). With the recovery key it reopens
 * a vault whose header files are all lost.
 */
export type RecoveryKit = Record<string, unknown>;

export interface RecoveryKeyResult {
  recovery_key: string;
  recovery_kit: RecoveryKit;
}

export interface BackupResult {
  path: string;
  generation: number;
  evidence_files: number;
  bytes: number;
}

export interface VerifyResult {
  evidence: number;
  verified: number;
  missing: string[];
  corrupt: string[];
  orphaned_files: number;
}

// ---------------------------------------------------------------- domain


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
  finding_counts: Partial<Record<Severity, number>>;
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
  /** Profile name at the time of logging, so exported logs stay attributable. */
  operator: string;
  created_at: string;
}

/** One entry of the vault's append-only activity log (AuditEvent on the backend). */
export interface ActivityEvent {
  id: number;
  engagement_id: number | null;
  action: string;
  entity_type: string;
  entity_id: number | null;
  summary: string;
  created_at: string;
}

export interface Dashboard {
  engagements_by_status: Partial<Record<EngagementStatus, number>>;
  open_findings_by_severity: Partial<Record<Severity, number>>;
  open_tests: number;
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

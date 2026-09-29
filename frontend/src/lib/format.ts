import type {
  EngagementStatus,
  EngagementType,
  FindingStatus,
  ScopeKind,
  Severity,
  TargetKind,
  TargetStatus,
  TestStatus,
} from "../types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const ENGAGEMENT_TYPES: Record<EngagementType, string> = {
  external_network: "External network",
  internal_network: "Internal network",
  web_application: "Web application",
  api: "API",
  mobile: "Mobile",
  cloud: "Cloud",
  wireless: "Wireless",
  social_engineering: "Social engineering",
  red_team: "Red team",
  physical: "Physical",
  other: "Other",
};

export const ENGAGEMENT_STATUSES: EngagementStatus[] = [
  "planning",
  "active",
  "reporting",
  "review",
  "delivered",
  "closed",
];

export const FINDING_STATUSES: Record<FindingStatus, string> = {
  draft: "Draft",
  confirmed: "Confirmed",
  reported: "Reported",
  remediated: "Remediated",
  risk_accepted: "Risk accepted",
  false_positive: "False positive",
};

export const TEST_STATUSES: Record<TestStatus, string> = {
  not_started: "Not started",
  in_progress: "In progress",
  passed: "Passed",
  failed: "Vulnerable",
  not_applicable: "N/A",
  blocked: "Blocked",
};

export const TARGET_KINDS: TargetKind[] = ["host", "domain", "web", "api", "network", "cloud", "mobile", "other"];
export const TARGET_STATUSES: Record<TargetStatus, string> = {
  new: "New",
  in_progress: "In progress",
  tested: "Tested",
  compromised: "Compromised",
};

export const SCOPE_KINDS: Record<ScopeKind, { label: string; example: string }> = {
  ip: { label: "IP address", example: "203.0.113.10" },
  cidr: { label: "CIDR range", example: "203.0.113.0/24" },
  range: { label: "IP range", example: "10.0.0.10-10.0.0.50" },
  domain: { label: "Hostname", example: "app.example.com" },
  wildcard: { label: "Wildcard (subdomains)", example: "*.example.com" },
  url: { label: "URL prefix", example: "https://app.example.com/api" },
  other: { label: "Other (exact)", example: "AWS account 123456789012" },
};

export function titleCase(s: string): string {
  return s.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso.length === 10 ? `${iso}T00:00:00` : iso);
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtRelative(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`;
  return fmtDate(iso);
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function daysUntil(isoDate: string | null): number | null {
  if (!isoDate) return null;
  const end = new Date(`${isoDate}T23:59:59`).getTime();
  return Math.ceil((end - Date.now()) / 86400000);
}

/** Guess the scope kind for a pasted value (used by bulk scope entry). */
export function guessScopeKind(value: string): ScopeKind {
  const v = value.trim();
  if (/^https?:\/\//i.test(v)) return "url";
  if (v.startsWith("*.")) return "wildcard";
  if (/^[0-9a-f:.]+\/\d{1,3}$/i.test(v)) return "cidr";
  if (/^[0-9a-f:.]+\s*-\s*[0-9a-f:.]+$/i.test(v) && /[.:]/.test(v)) return "range";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (/^[0-9a-f:]+$/i.test(v) && v.includes(":"))) return "ip";
  if (/^[a-z0-9_.-]+$/i.test(v) && /[a-z]/i.test(v)) return "domain";
  return "other";
}

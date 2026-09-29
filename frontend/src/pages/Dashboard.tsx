import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../api";
import {
  Card,
  Empty,
  ErrorBox,
  FindingStatusBadge,
  Loading,
  PageHeader,
  SeverityBadge,
  SeverityCounts,
  Stat,
  StatusPill,
} from "../components/ui";
import { daysUntil, ENGAGEMENT_TYPES, fmtDate, fmtRelative, SEVERITIES } from "../lib/format";
import type { Dashboard as DashboardData } from "../types";
import { useProfile } from "../vault/context";

export function Dashboard() {
  const profile = useProfile();
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => api.get<DashboardData>("/api/dashboard") });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data!;
  const open = d.open_findings_by_severity;
  const openTotal = SEVERITIES.reduce((n, s) => n + (open[s] ?? 0), 0);
  const maxSev = Math.max(1, ...SEVERITIES.map((s) => open[s] ?? 0));
  const active = (d.engagements_by_status.active ?? 0) + (d.engagements_by_status.planning ?? 0);
  const firstName = profile.data?.name.split(" ")[0];

  return (
    <>
      <PageHeader title={firstName ? `Welcome back, ${firstName}` : "Dashboard"} subtitle="Your engagements at a glance" />
      {profile.data && !profile.data.name && (
        <div className="alert alert-info">
          <Link to="/settings">Add your name and organization</Link> in Settings. They appear on reports and sign your op-log
          entries.
        </div>
      )}
      <div className="stats">
        <Stat label="Active & planned engagements" value={active} />
        <Stat label="In reporting / review" value={(d.engagements_by_status.reporting ?? 0) + (d.engagements_by_status.review ?? 0)} />
        <Stat label="Open findings" value={openTotal} hint="draft, confirmed or reported" />
        <Stat label="Critical + high open" value={(open.critical ?? 0) + (open.high ?? 0)} tone={(open.critical ?? 0) + (open.high ?? 0) ? "red" : undefined} />
        <Stat label="Open test cases" value={d.open_tests} hint="not started, in progress or blocked" />
      </div>

      <div className="grid-2-1">
        <Card title="Current engagements">
          {d.active_engagements.length === 0 ? (
            <Empty title="No active engagements">
              <Link to="/engagements">Create or open an engagement</Link>
            </Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Engagement</th>
                  <th>Status</th>
                  <th>Ends</th>
                  <th>Findings (C/H/M/L/I)</th>
                </tr>
              </thead>
              <tbody>
                {d.active_engagements.map((e) => {
                  const left = daysUntil(e.end_date);
                  return (
                    <tr key={e.id}>
                      <td>
                        <Link to={`/engagements/${e.id}`} className="strong">
                          {e.name}
                        </Link>
                        <div className="muted small">
                          <span className="mono">{e.code}</span> · {e.client.name} · {ENGAGEMENT_TYPES[e.type]}
                        </div>
                      </td>
                      <td>
                        <StatusPill status={e.status} />
                      </td>
                      <td>
                        {fmtDate(e.end_date)}
                        {left !== null && (
                          <div className={`small ${left < 0 ? "error-text" : left <= 3 ? "warn-text" : "muted"}`}>
                            {left < 0 ? `${-left}d overdue` : `${left}d left`}
                          </div>
                        )}
                      </td>
                      <td>
                        <SeverityCounts counts={e.finding_counts} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>

        <div className="stack">
          <Card title="Open findings by severity">
            {SEVERITIES.map((s) => (
              <div key={s} className="hbar">
                <SeverityBadge severity={s} />
                <div className="hbar-track">
                  <div className={`hbar-fill sev-bg-${s}`} style={{ width: `${((open[s] ?? 0) / maxSev) * 100}%` }} />
                </div>
                <strong>{open[s] ?? 0}</strong>
              </div>
            ))}
          </Card>
          <Card title="Latest findings">
            {d.recent_findings.length === 0 ? (
              <Empty title="Nothing reported yet" />
            ) : (
              <ul className="list">
                {d.recent_findings.map((f) => (
                  <li key={f.id}>
                    <Link to={`/engagements/${f.engagement_id}/findings/${f.id}`}>
                      <SeverityBadge severity={f.severity} /> <span className="strong">{f.title}</span>
                    </Link>
                    <div className="muted small">
                      <span className="mono">{f.ref}</span> · <FindingStatusBadge status={f.status} /> · {fmtRelative(f.created_at)}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}

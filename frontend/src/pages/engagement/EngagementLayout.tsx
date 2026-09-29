import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, Outlet, useParams } from "react-router";
import { api } from "../../api";
import { useUser } from "../../auth";
import { ErrorBox, Loading, StatusPill } from "../../components/ui";
import { daysUntil, ENGAGEMENT_TYPES, fmtDate } from "../../lib/format";
import type { Engagement } from "../../types";
import { permissions, type EngagementCtx } from "./context";

const TABS = [
  { to: "", label: "Overview", end: true },
  { to: "scope", label: "Scope" },
  { to: "targets", label: "Targets" },
  { to: "recon", label: "Recon" },
  { to: "testing", label: "Testing" },
  { to: "findings", label: "Findings" },
  { to: "evidence", label: "Evidence" },
  { to: "oplog", label: "Op log" },
  { to: "report", label: "Report" },
  { to: "activity", label: "Activity" },
];

export function EngagementLayout() {
  const { engagementId } = useParams();
  const user = useUser();
  const base = `/api/engagements/${engagementId}`;
  const q = useQuery({ queryKey: [base], queryFn: () => api.get<Engagement>(base) });

  if (q.isLoading) return <Loading />;
  if (q.error || !q.data) return <ErrorBox error={q.error ?? "Engagement not found"} />;
  const e = q.data;
  const ctx: EngagementCtx = { engagement: e, base, ...permissions(e, user) };
  const left = daysUntil(e.end_date);

  return (
    <>
      <div className="eng-header">
        <div className="crumbs">
          <Link to="/engagements">Engagements</Link> / <span className="mono">{e.code}</span>
        </div>
        <div className="eng-title">
          <h1>{e.name}</h1>
          <StatusPill status={e.status} />
          {!ctx.canWrite && <span className="badge badge-muted">Read-only</span>}
        </div>
        <div className="muted">
          {e.client.name} · {ENGAGEMENT_TYPES[e.type]} · {fmtDate(e.start_date)} to {fmtDate(e.end_date)}
          {left !== null && e.status !== "delivered" && e.status !== "closed" && (
            <span className={left < 0 ? "error-text" : left <= 3 ? "warn-text" : ""}>
              {" "}
              · {left < 0 ? `${-left} days past end date` : `${left} days left`}
            </span>
          )}
        </div>
        <nav className="tabs">
          {TABS.map((t) => (
            <NavLink key={t.label} to={t.to} end={t.end} className={({ isActive }) => (isActive ? "active" : "")}>
              {t.label}
            </NavLink>
          ))}
        </nav>
      </div>
      <Outlet context={ctx} />
    </>
  );
}

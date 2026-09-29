import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../../api";
import { Badge, Card, Empty, Loading } from "../../components/ui";
import { fmtDateTime } from "../../lib/format";
import type { AuditEvent } from "../../types";
import { useEngagement } from "./context";

const ACTION_TONE: Record<string, string> = {
  create: "green",
  update: "blue",
  delete: "red",
  import: "teal",
  export: "amber",
  login: "neutral",
  login_failed: "red",
};

export function Activity() {
  const { base } = useEngagement();
  const q = useQuery({ queryKey: [base, "activity"], queryFn: () => api.get<AuditEvent[]>(`${base}/activity?limit=500`) });
  return (
    <Card title="Audit trail">
      <p className="muted small">Append-only record of every change, import, export and deletion in this engagement.</p>
      {q.isLoading ? <Loading /> : <AuditTable events={q.data ?? []} />}
    </Card>
  );
}

export function AuditTable({ events, showEngagement }: { events: AuditEvent[]; showEngagement?: boolean }) {
  if (!events.length) return <Empty title="No activity yet" />;
  return (
    <table className="table">
      <thead>
        <tr>
          <th>When</th>
          <th>Who</th>
          <th>Action</th>
          <th>What</th>
          {showEngagement && <th>Engagement</th>}
          <th>IP</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e) => (
          <tr key={e.id}>
            <td className="small nowrap">{fmtDateTime(e.created_at)}</td>
            <td className="small">{e.user?.full_name ?? "system"}</td>
            <td><Badge tone={ACTION_TONE[e.action] ?? "neutral"}>{e.action.replace("_", " ")}</Badge></td>
            <td className="small">
              <span className="muted">{e.entity_type.replace("_", " ")}</span> {e.summary}
            </td>
            {showEngagement && (
              <td className="small">{e.engagement_id ? <Link to={`/engagements/${e.engagement_id}/activity`}>#{e.engagement_id}</Link> : "-"}</td>
            )}
            <td className="mono small muted">{e.ip_address}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

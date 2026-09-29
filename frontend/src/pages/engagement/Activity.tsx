import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../../api";
import { Badge, Card, Empty, Loading } from "../../components/ui";
import { fmtDateTime, titleCase } from "../../lib/format";
import type { ActivityEvent } from "../../types";
import { useEngagement } from "./context";

const ACTION_TONE: Record<string, string> = {
  create: "green",
  update: "blue",
  delete: "red",
  import: "teal",
  export: "amber",
  unlock: "neutral",
};

export function Activity() {
  const { base } = useEngagement();
  const q = useQuery({ queryKey: [base, "activity"], queryFn: () => api.get<ActivityEvent[]>(`${base}/activity?limit=500`) });
  return (
    <Card title="Activity">
      <p className="muted small">Append-only record of every change, import, export and deletion in this engagement.</p>
      {q.isLoading ? <Loading /> : <ActivityTable events={q.data ?? []} />}
    </Card>
  );
}

/** With `engagementCodes`, adds an engagement column (the vault-wide view). */
export function ActivityTable({ events, engagementCodes }: { events: ActivityEvent[]; engagementCodes?: Map<number, string> }) {
  if (!events.length) return <Empty title="No activity yet" />;
  return (
    <table className="table">
      <thead>
        <tr>
          <th>When</th>
          <th>Action</th>
          <th>What</th>
          {engagementCodes && <th>Engagement</th>}
        </tr>
      </thead>
      <tbody>
        {events.map((e) => (
          <tr key={e.id}>
            <td className="small nowrap">{fmtDateTime(e.created_at)}</td>
            <td>
              <Badge tone={ACTION_TONE[e.action] ?? "neutral"}>{titleCase(e.action)}</Badge>
            </td>
            <td className="small">
              <span className="muted">{titleCase(e.entity_type)}</span> {e.summary}
            </td>
            {engagementCodes && (
              <td className="small nowrap">
                {e.engagement_id == null ? (
                  "-"
                ) : (
                  <Link className="mono" to={`/engagements/${e.engagement_id}/activity`}>
                    {engagementCodes.get(e.engagement_id) ?? `#${e.engagement_id}`}
                  </Link>
                )}
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

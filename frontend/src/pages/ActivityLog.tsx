import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { Card, ErrorBox, Loading, PageHeader } from "../components/ui";
import type { ActivityEvent, Engagement } from "../types";
import { ActivityTable } from "./engagement/Activity";

/** Vault-wide activity: every change, import, export, deletion and vault event. */
export function ActivityLog() {
  const q = useQuery({ queryKey: ["activity"], queryFn: () => api.get<ActivityEvent[]>("/api/activity?limit=500") });
  const engagements = useQuery({
    queryKey: ["engagements", ""],
    queryFn: () => api.get<Engagement[]>("/api/engagements"),
  });
  const codes = new Map(engagements.data?.map((e) => [e.id, e.code]));
  return (
    <>
      <PageHeader
        title="Activity"
        subtitle="Append-only record of every change, import, export and deletion in this vault, plus unlocks and key changes."
      />
      <Card>
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <ErrorBox error={q.error} />
        ) : (
          <ActivityTable events={q.data!} engagementCodes={codes} />
        )}
      </Card>
    </>
  );
}

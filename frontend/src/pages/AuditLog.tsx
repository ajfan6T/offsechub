import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { AuditTable } from "./engagement/Activity";
import { Card, ErrorBox, Loading, PageHeader } from "../components/ui";
import type { AuditEvent } from "../types";

export function AuditLog() {
  const q = useQuery({ queryKey: ["audit"], queryFn: () => api.get<AuditEvent[]>("/api/audit?limit=500") });
  return (
    <>
      <PageHeader title="Audit log" subtitle="Every sign-in, change, export and deletion across the platform." />
      <Card>{q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : <AuditTable events={q.data!} showEngagement />}</Card>
    </>
  );
}

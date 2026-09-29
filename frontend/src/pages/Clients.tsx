import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";
import { Button, Card, Empty, ErrorBox, Field, Loading, Modal, PageHeader, useApiMutation } from "../components/ui";
import type { Client } from "../types";

export function Clients() {
  const [editing, setEditing] = useState<Client | "new" | null>(null);
  const q = useQuery({ queryKey: ["clients"], queryFn: () => api.get<Client[]>("/api/clients") });

  return (
    <>
      <PageHeader
        title="Clients"
        subtitle="Organisations you test for."
        actions={
          <Button variant="primary" onClick={() => setEditing("new")}>
            New client
          </Button>
        }
      />
      <Card>
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <ErrorBox error={q.error} />
        ) : !q.data?.length ? (
          <Empty title="No clients yet" />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Industry</th>
                <th>Contact</th>
                <th>Engagements</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data.map((c) => (
                <tr key={c.id}>
                  <td className="strong">{c.name}</td>
                  <td>{c.industry || "-"}</td>
                  <td>
                    {c.contact_name || "-"}
                    {c.contact_email && <div className="muted small">{c.contact_email}</div>}
                  </td>
                  <td>{c.engagement_count}</td>
                  <td className="right">
                    <Button size="sm" variant="ghost" onClick={() => setEditing(c)}>
                      Edit
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {editing && <ClientForm client={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );
}

function ClientForm({ client, onClose }: { client: Client | null; onClose: () => void }) {
  const [form, setForm] = useState({
    name: client?.name ?? "",
    industry: client?.industry ?? "",
    contact_name: client?.contact_name ?? "",
    contact_email: client?.contact_email ?? "",
    notes: client?.notes ?? "",
  });
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const save = useApiMutation(
    () => (client ? api.patch(`/api/clients/${client.id}`, form) : api.post("/api/clients", form)),
    { invalidate: [["clients"]], success: "Client saved", onSuccess: onClose },
  );
  const remove = useApiMutation(() => api.del(`/api/clients/${client!.id}`), {
    invalidate: [["clients"]],
    success: "Client deleted",
    onSuccess: onClose,
  });

  return (
    <Modal
      title={client ? `Edit ${client.name}` : "New client"}
      onClose={onClose}
      footer={
        <>
          {client && (
            <Button
              variant="danger"
              className="mr-auto"
              loading={remove.isPending}
              onClick={() => window.confirm(`Delete ${client.name}?`) && remove.mutate(undefined)}
            >
              Delete
            </Button>
          )}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={save.isPending} disabled={!form.name} onClick={() => save.mutate(undefined)}>
            Save
          </Button>
        </>
      }
    >
      <div className="form-grid">
        <Field label="Name">
          <input value={form.name} onChange={set("name")} autoFocus />
        </Field>
        <Field label="Industry">
          <input value={form.industry} onChange={set("industry")} />
        </Field>
        <Field label="Contact name">
          <input value={form.contact_name} onChange={set("contact_name")} />
        </Field>
        <Field label="Contact email">
          <input type="email" value={form.contact_email} onChange={set("contact_email")} />
        </Field>
        <Field label="Notes" wide>
          <textarea rows={3} value={form.notes} onChange={set("notes")} />
        </Field>
      </div>
    </Modal>
  );
}

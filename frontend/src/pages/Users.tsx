import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";
import { useUser } from "../auth";
import { Badge, Button, Card, ErrorBox, Field, Loading, Modal, PageHeader, useApiMutation } from "../components/ui";
import { fmtRelative } from "../lib/format";
import type { Role, User } from "../types";

const ROLE_HELP: Record<Role, string> = {
  admin: "Everything, including users and all engagements",
  lead: "Creates engagements and clients, curates the finding library",
  tester: "Works on engagements they are assigned to",
  viewer: "Read-only access to assigned engagements (e.g. client stakeholders)",
};

export function Users() {
  const me = useUser();
  const [editing, setEditing] = useState<User | "new" | null>(null);
  const q = useQuery({ queryKey: ["users"], queryFn: () => api.get<User[]>("/api/users") });
  return (
    <>
      <PageHeader
        title="Users"
        subtitle="Accounts and global roles. Engagement access is granted per engagement."
        actions={
          <Button variant="primary" onClick={() => setEditing("new")}>
            New user
          </Button>
        }
      />
      <Card>
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <ErrorBox error={q.error} />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last sign-in</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data!.map((u) => (
                <tr key={u.id}>
                  <td className="strong">
                    {u.full_name} {u.id === me.id && <span className="muted small">(you)</span>}
                  </td>
                  <td>{u.email}</td>
                  <td>{u.role}</td>
                  <td>{u.is_active ? <Badge tone="green">Active</Badge> : <Badge tone="muted">Disabled</Badge>}</td>
                  <td className="muted">{u.last_login_at ? fmtRelative(u.last_login_at) : "never"}</td>
                  <td className="right">
                    <Button size="sm" variant="ghost" onClick={() => setEditing(u)}>
                      Edit
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {editing && <UserForm user={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );
}

function UserForm({ user, onClose }: { user: User | null; onClose: () => void }) {
  const [form, setForm] = useState({
    email: user?.email ?? "",
    full_name: user?.full_name ?? "",
    role: (user?.role ?? "tester") as Role,
    is_active: user?.is_active ?? true,
    password: "",
  });
  const save = useApiMutation(
    () => {
      if (!user) return api.post("/api/users", form);
      const { email: _email, password, ...rest } = form;
      return api.patch(`/api/users/${user.id}`, password ? { ...rest, password } : rest);
    },
    { invalidate: [["users"]], success: "User saved", onSuccess: onClose },
  );
  return (
    <Modal
      title={user ? `Edit ${user.full_name}` : "New user"}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={save.isPending} onClick={() => save.mutate(undefined)}>
            Save
          </Button>
        </>
      }
    >
      <div className="form-grid">
        <Field label="Full name">
          <input value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
        </Field>
        <Field label="Email">
          <input type="email" value={form.email} disabled={!!user} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        </Field>
        <Field label="Role" hint={ROLE_HELP[form.role]}>
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
            {(Object.keys(ROLE_HELP) as Role[]).map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </Field>
        {user && (
          <Field label="Status" hint="Disabling revokes all sessions and API tokens">
            <select value={form.is_active ? "1" : "0"} onChange={(e) => setForm({ ...form, is_active: e.target.value === "1" })}>
              <option value="1">Active</option>
              <option value="0">Disabled</option>
            </select>
          </Field>
        )}
        <Field
          label={user ? "Reset password" : "Initial password"}
          hint={user ? "Leave blank to keep. Resetting revokes all sessions." : "At least 12 characters"}
          wide
        >
          <input
            type="password"
            autoComplete="new-password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
          />
        </Field>
      </div>
    </Modal>
  );
}

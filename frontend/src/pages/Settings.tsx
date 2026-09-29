import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";
import { useUser } from "../auth";
import {
  Button,
  Card,
  ConfirmButton,
  CopyButton,
  Empty,
  Field,
  PageHeader,
  useApiMutation,
} from "../components/ui";
import { fmtDate, fmtRelative } from "../lib/format";
import type { ApiToken } from "../types";

export function Settings() {
  const user = useUser();
  return (
    <>
      <PageHeader title="Settings" subtitle={`${user.full_name} · ${user.email} · ${user.role}`} />
      <div className="grid-2">
        <PasswordCard />
        <TokensCard />
      </div>
    </>
  );
}

function PasswordCard() {
  const [form, setForm] = useState({ current_password: "", new_password: "", confirm: "" });
  const change = useApiMutation(
    () => api.post("/api/auth/change-password", { current_password: form.current_password, new_password: form.new_password }),
    {
      success: "Password changed. Other sessions were signed out.",
      onSuccess: () => setForm({ current_password: "", new_password: "", confirm: "" }),
    },
  );
  const mismatch = form.confirm !== "" && form.confirm !== form.new_password;
  return (
    <Card title="Change password">
      <div className="form-grid single">
        <Field label="Current password">
          <input type="password" autoComplete="current-password" value={form.current_password} onChange={(e) => setForm({ ...form, current_password: e.target.value })} />
        </Field>
        <Field label="New password" hint="At least 12 characters">
          <input type="password" autoComplete="new-password" value={form.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} />
        </Field>
        <Field label="Confirm new password" hint={mismatch ? <span className="error-text">Passwords do not match</span> : undefined}>
          <input type="password" autoComplete="new-password" value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} />
        </Field>
      </div>
      <Button
        variant="primary"
        loading={change.isPending}
        disabled={!form.current_password || !form.new_password || mismatch || !form.confirm}
        onClick={() => change.mutate(undefined)}
      >
        Change password
      </Button>
    </Card>
  );
}

function TokensCard() {
  const [name, setName] = useState("");
  const [days, setDays] = useState("90");
  const [created, setCreated] = useState<ApiToken | null>(null);
  const tokens = useQuery({ queryKey: ["tokens"], queryFn: () => api.get<ApiToken[]>("/api/auth/tokens") });
  const create = useApiMutation(
    () => api.post<ApiToken>("/api/auth/tokens", { name, expires_in_days: Number(days) }),
    {
      invalidate: [["tokens"]],
      onSuccess: (t) => {
        setCreated(t);
        setName("");
      },
    },
  );
  const revoke = useApiMutation((id: number) => api.del(`/api/auth/tokens/${id}`), {
    invalidate: [["tokens"]],
    success: "Token revoked",
  });
  const origin = window.location.origin;

  return (
    <Card title="API tokens">
      <p className="muted">
        Push tool output from your attack box or CI straight into an engagement. Tokens act as you, with your
        permissions.
      </p>
      {created?.token && (
        <div className="alert alert-success">
          <strong>Copy this token now. It will not be shown again.</strong>
          <div className="token-row">
            <code className="mono">{created.token}</code>
            <CopyButton text={created.token} />
          </div>
          <pre className="code">{`curl -H "Authorization: Bearer ${created.token.slice(0, 10)}..." \\
  -F tool=nmap -F file=@scan.xml \\
  ${origin}/api/engagements/<ID>/imports`}</pre>
        </div>
      )}
      <div className="inline-form">
        <input placeholder="Token name (e.g. kali-laptop)" value={name} onChange={(e) => setName(e.target.value)} />
        <select value={days} onChange={(e) => setDays(e.target.value)}>
          <option value="7">7 days</option>
          <option value="30">30 days</option>
          <option value="90">90 days</option>
          <option value="365">1 year</option>
        </select>
        <Button variant="primary" disabled={!name} loading={create.isPending} onClick={() => create.mutate(undefined)}>
          Create
        </Button>
      </div>
      {!tokens.data?.length ? (
        <Empty title="No API tokens" />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Last used</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {tokens.data.map((t) => (
              <tr key={t.id}>
                <td className="strong">{t.name}</td>
                <td>{fmtDate(t.created_at)}</td>
                <td>{t.expires_at ? fmtDate(t.expires_at) : "never"}</td>
                <td className="muted">{t.last_used_at ? fmtRelative(t.last_used_at) : "never"}</td>
                <td className="right">
                  <ConfirmButton size="sm" variant="ghost" message={`Revoke ${t.name}?`} onConfirm={() => revoke.mutate(t.id)}>
                    Revoke
                  </ConfirmButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

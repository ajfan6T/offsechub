import { useState, type FormEvent } from "react";
import { api } from "../api";
import { Button, Field } from "../components/ui";
import { joinPath, safeFileName, useDesktopBridge } from "../lib/desktop";
import type { VaultStatus } from "../types";
import { useAppInfo, useVault } from "./context";
import { EMPTY_PASSWORD, errorText, isValidNewPassword, NewPasswordFields, PathField, VaultScreen } from "./common";

export function CreateVault({ onCancel }: { onCancel: () => void }) {
  const { setStatus, showRecoveryKey } = useVault();
  const info = useAppInfo();
  const bridge = useDesktopBridge();
  const [name, setName] = useState("");
  const [folder, setFolder] = useState<string | null>(null);
  const [password, setPassword] = useState(EMPTY_PASSWORD);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const dir = folder ?? info.data?.default_vault_dir ?? "";
  const fileName = safeFileName(name).replace(/\.ohvault$/i, "");
  const path = fileName && dir ? joinPath(dir, `${fileName}.ohvault`) : "";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<{ recovery_key: string; status: VaultStatus }>("/api/vault/create", {
        path,
        password: password.password,
      });
      // The vault is already unlocked; the gate keeps the recovery key on screen until it is confirmed.
      showRecoveryKey(res.recovery_key, "created");
      setStatus(res.status);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  return (
    <VaultScreen title="Create a vault" subtitle="One vault per client, year or engagement: your call." wide>
      <form className="gate-form" onSubmit={submit}>
        <Field label="Vault name" hint="The folder name is visible on disk. Use a code name if the client's identity is sensitive.">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="ACME-2026" autoFocus />
        </Field>
        <PathField label="Location" value={dir} onChange={setFolder} pick={bridge ? () => bridge.pick_folder() : undefined} />
        {path && (
          <p className="small muted">
            Creates <span className="mono">{path}</span>
          </p>
        )}
        <NewPasswordFields value={password} onChange={setPassword} />
        <div className="alert alert-warn small">
          There is no account and no password reset. If you forget the password, only the recovery key shown on the next
          screen can open this vault.
        </div>
        {error && <div className="alert alert-error">{error}</div>}
        <div className="actions gate-actions">
          <Button type="button" onClick={onCancel}>
            Back
          </Button>
          <Button variant="primary" type="submit" loading={busy} disabled={!path || !isValidNewPassword(password)}>
            {busy ? "Creating vault" : "Create vault"}
          </Button>
        </div>
      </form>
    </VaultScreen>
  );
}

import { useState, type FormEvent } from "react";
import { api } from "../api";
import { Button, Field, useApiMutation } from "../components/ui";
import type { RecoveryKeyResult } from "../types";
import { useVault } from "./context";
import { EMPTY_PASSWORD, errorText, isValidNewPassword, NewPasswordFields, VaultScreen } from "./common";

/**
 * After a recovery-key unlock nothing else is available until a new password
 * is set. The backend also rotates the recovery key, since it has now been
 * typed in outside its safe place.
 */
export function SetPassword({ typedRecoveryKey }: { typedRecoveryKey: string | null }) {
  const { status, setStatus, showRecoveryKey, lock } = useVault();
  const [recoveryKey, setRecoveryKey] = useState(typedRecoveryKey ?? "");
  const [password, setPassword] = useState(EMPTY_PASSWORD);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const lockVault = useApiMutation(() => lock());

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<RecoveryKeyResult>("/api/vault/reset-password", {
        recovery_key: recoveryKey,
        new_password: password.password,
      });
      showRecoveryKey(res.recovery_key, "reset");
      setStatus({ ...status, must_set_password: false });
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  return (
    <VaultScreen title="Set a new password" subtitle={`${status.name} was unlocked with its recovery key.`}>
      <form className="gate-form" onSubmit={submit}>
        <p className="muted small">
          Choose a new password before continuing. A new recovery key is generated at the same time, and the one you just
          used stops working.
        </p>
        {!typedRecoveryKey && (
          <Field label="Recovery key">
            <input className="mono" value={recoveryKey} onChange={(e) => setRecoveryKey(e.target.value)} autoComplete="off" spellCheck={false} autoFocus />
          </Field>
        )}
        <NewPasswordFields label="New password" value={password} onChange={setPassword} autoFocus={!!typedRecoveryKey} />
        {error && <div className="alert alert-error">{error}</div>}
        <Button variant="primary" type="submit" className="btn-block" loading={busy} disabled={!recoveryKey || !isValidNewPassword(password)}>
          Set password
        </Button>
        <div className="gate-links">
          <button type="button" className="link small" disabled={lockVault.isPending} onClick={() => lockVault.mutate(undefined)}>
            Lock the vault instead
          </button>
        </div>
      </form>
    </VaultScreen>
  );
}

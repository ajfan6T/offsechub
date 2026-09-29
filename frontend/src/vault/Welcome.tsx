import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";
import { Badge, Button, useApiMutation } from "../components/ui";
import type { RecentVault } from "../types";
import { RECENT_KEY, useRecentVaults } from "./context";
import { VaultScreen } from "./common";
import { CreateVault } from "./CreateVault";
import { UnlockForm } from "./Unlock";

type View = { kind: "home" } | { kind: "create" } | { kind: "open"; vault?: RecentVault };

/** No vault selected: pick a recent one, open another, or create one. */
export function Welcome() {
  const [view, setView] = useState<View>({ kind: "home" });
  const home = () => setView({ kind: "home" });
  const back = (
    <button type="button" className="link small" onClick={home}>
      Back
    </button>
  );

  if (view.kind === "create") return <CreateVault onCancel={home} />;
  if (view.kind === "open")
    return view.vault ? (
      <VaultScreen title={`Unlock ${view.vault.name}`} subtitle={<span className="mono small">{view.vault.path}</span>}>
        <UnlockForm path={view.vault.path} secondary={back} />
      </VaultScreen>
    ) : (
      <VaultScreen title="Open a vault">
        <UnlockForm path="" editablePath secondary={back} />
      </VaultScreen>
    );

  return (
    <VaultScreen wide subtitle="Your engagements, encrypted on this machine. No account, no server, nothing leaves your disk.">
      <RecentList onOpen={(vault) => setView({ kind: "open", vault })} />
      <div className="actions gate-actions">
        <Button onClick={() => setView({ kind: "open" })}>Open vault…</Button>
        <Button variant="primary" onClick={() => setView({ kind: "create" })}>
          Create vault
        </Button>
      </div>
      <p className="muted small">
        A vault is one encrypted folder holding scope, targets, findings, evidence and op logs for a body of work. Back it up
        like any other folder; the copies stay encrypted.
      </p>
    </VaultScreen>
  );
}

function RecentList({ onOpen }: { onOpen: (vault: RecentVault) => void }) {
  const qc = useQueryClient();
  const recent = useRecentVaults();
  const forget = useApiMutation((path: string) => api.post("/api/app/recent/forget", { path }), {
    onSuccess: () => qc.invalidateQueries({ queryKey: RECENT_KEY }),
  });
  const vaults = recent.data?.vaults ?? [];
  if (!vaults.length) return null;
  return (
    <div>
      <h3>Recent vaults</h3>
      <ul className="recent-list">
        {vaults.map((v) => (
          <li key={v.path}>
            <div className="recent-name">
              <strong>{v.name}</strong> {!v.exists && <Badge tone="amber">Not found</Badge>}
              <div className="mono small muted">{v.path}</div>
            </div>
            <Button size="sm" variant="primary" disabled={!v.exists} onClick={() => onOpen(v)}>
              Open
            </Button>
            <Button size="sm" variant="ghost" onClick={() => forget.mutate(v.path)} title="Remove from this list (the vault itself is not touched)">
              Forget
            </Button>
          </li>
        ))}
      </ul>
    </div>
  );
}

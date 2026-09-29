import { useState } from "react";
import { NavLink, Outlet } from "react-router";
import type { VaultStatus } from "../types";
import { useProfile, useVault } from "../vault/context";
import { Button, Logo, useApiMutation } from "./ui";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/engagements", label: "Engagements" },
  { to: "/clients", label: "Clients" },
  { to: "/library", label: "Finding library" },
  { to: "/activity", label: "Activity" },
];

export function Layout() {
  const { status, lock } = useVault();
  const profile = useProfile();
  const lockNow = useApiMutation(() => lock());
  const name = profile.data?.name ?? "";
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Logo />
          <span>OffsecHub</span>
        </div>
        <div className="vault-chip" title={status.path ?? undefined}>
          <span>
            <strong>{status.name}</strong>
            <small>{status.auto_lock_minutes ? `Auto-locks after ${status.auto_lock_minutes} min idle` : "Auto-lock off"}</small>
          </span>
          <Button size="sm" loading={lockNow.isPending} onClick={() => lockNow.mutate(undefined)} title="Lock the vault (Settings has more options)">
            Lock
          </Button>
        </div>
        <nav>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => (isActive ? "active" : "")}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <NavLink to="/settings" className="user-chip">
            <span className="avatar">{initials(name) || "+"}</span>
            <span>
              <strong>{name || "Set up your profile"}</strong>
              <small>Settings</small>
            </span>
          </NavLink>
        </div>
      </aside>
      <main className="main">
        <VaultBanners status={status} />
        <Outlet />
      </main>
    </div>
  );
}

/** Save failures stay until a save succeeds; unlock warnings and notices can be dismissed. */
function VaultBanners({ status }: { status: VaultStatus }) {
  const [dismissed, setDismissed] = useState<string[]>([]);
  const dismissible = (tone: "error" | "info", messages: string[]) =>
    messages
      .filter((m) => !dismissed.includes(m))
      .map((m) => (
        <div key={m} className={`alert alert-${tone} alert-dismissible`} role={tone === "error" ? "alert" : "status"}>
          <span>{m}</span>
          <button className="icon-btn" aria-label="Dismiss" onClick={() => setDismissed([...dismissed, m])}>
            ×
          </button>
        </div>
      ));
  return (
    <>
      {status.save_error && (
        <div className="alert alert-error" role="alert">
          <strong>Changes are not being saved.</strong> {status.save_error}
          <div className="small">
            OffsecHub keeps retrying. Until a save succeeds, recent changes exist only in memory: free up disk space or fix
            the vault folder's permissions, and keep OffsecHub open.
          </div>
        </div>
      )}
      {dismissible("error", status.warnings)}
      {dismissible("info", status.notices)}
    </>
  );
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join("");
}

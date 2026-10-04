import { useQuery, type Query } from "@tanstack/react-query";
import { createContext, useContext } from "react";
import { api } from "../api";
import type { AppInfo, Profile, RecentVaults, RecoveryKit, VaultStatus } from "../types";

// Query keys under "app" do not depend on an unlocked vault and survive a lock.
// Every other query holds decrypted vault data and is dropped when the vault locks.
export const STATUS_KEY = ["app", "status"] as const;
export const INFO_KEY = ["app", "info"] as const;
export const RECENT_KEY = ["app", "recent"] as const;
export const PROFILE_KEY = ["profile"] as const;

export const isAppQuery = (q: Query) => q.queryKey[0] === "app";

/** Why a recovery key is on screen; picks the wording of the show-once screen. */
export type RecoveryKeyReason = "created" | "reset" | "rotated" | "rekeyed";

export type UnlockSecret = { password: string } | { recovery_key: string; recovery_kit?: RecoveryKit };

/** Vault lifecycle, provided by the VaultGate to every screen and page. */
export interface VaultApi {
  status: VaultStatus;
  /** Store a status returned by a lifecycle endpoint. */
  setStatus: (status: VaultStatus) => void;
  /** Show a new recovery key full-screen until the operator confirms they stored it. */
  showRecoveryKey: (key: string, reason: RecoveryKeyReason) => void;
  unlock: (path: string, secret: UnlockSecret) => Promise<void>;
  lock: () => Promise<void>;
  /** Lock and go back to the vault picker. */
  close: () => Promise<void>;
}

export const VaultContext = createContext<VaultApi | null>(null);

export function useVault(): VaultApi {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault outside VaultGate");
  return ctx;
}

export function useAppInfo() {
  return useQuery({ queryKey: INFO_KEY, queryFn: () => api.get<AppInfo>("/api/app/info"), staleTime: Infinity });
}

export function useRecentVaults() {
  return useQuery({ queryKey: RECENT_KEY, queryFn: () => api.get<RecentVaults>("/api/app/recent") });
}

export function useProfile() {
  return useQuery({ queryKey: PROFILE_KEY, queryFn: () => api.get<Profile>("/api/profile"), staleTime: Infinity });
}

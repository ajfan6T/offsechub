import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, type ReactNode } from "react";
import { api, ApiError, setUnauthorizedHandler } from "./api";
import type { User } from "./types";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const me = useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        return await api.get<User>("/api/auth/me");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    staleTime: 60_000,
    retry: false,
  });

  // Swap the signed-in user and drop every other cached query. The ["me"] query
  // itself must stay in the cache: clearing it would detach the observer above.
  const switchUser = useCallback(
    (next: User | null) => {
      qc.setQueryData(["me"], next);
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
    },
    [qc],
  );

  useEffect(() => {
    setUnauthorizedHandler(() => switchUser(null));
  }, [switchUser]);

  const value: AuthState = {
    user: me.data ?? null,
    loading: me.isLoading,
    login: async (email, password) => {
      switchUser(await api.post<User>("/api/auth/login", { email, password }));
    },
    logout: async () => {
      try {
        await api.post("/api/auth/logout");
      } finally {
        switchUser(null);
      }
    },
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

/** The signed-in user (only call inside authenticated routes). */
export function useUser(): User {
  const { user } = useAuth();
  if (!user) throw new Error("not signed in");
  return user;
}

export const canLead = (u: User) => u.role === "admin" || u.role === "lead";

import { useQuery } from "@tanstack/react-query";
import { useOutletContext } from "react-router";
import { api } from "../../api";
import type { Engagement, Finding, Member, Target, User } from "../../types";

export interface EngagementCtx {
  engagement: Engagement;
  base: string; // API base path for this engagement
  canWrite: boolean;
  canManage: boolean;
}

export const useEngagement = () => useOutletContext<EngagementCtx>();

export function permissions(e: Engagement, user: User) {
  const canWrite = user.role === "admin" || (user.role !== "viewer" && (e.my_role === "lead" || e.my_role === "tester"));
  const canManage = user.role === "admin" || (user.role !== "viewer" && e.my_role === "lead");
  return { canWrite, canManage };
}

// Shared queries so every tab hits the same cache entries.
export function useTargets(base: string) {
  return useQuery({ queryKey: [base, "targets"], queryFn: () => api.get<Target[]>(`${base}/targets`) });
}

export function useFindings(base: string) {
  return useQuery({ queryKey: [base, "findings"], queryFn: () => api.get<Finding[]>(`${base}/findings`) });
}

export function useMembers(base: string) {
  return useQuery({ queryKey: [base, "members"], queryFn: () => api.get<Member[]>(`${base}/members`) });
}

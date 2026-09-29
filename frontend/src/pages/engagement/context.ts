import { useQuery } from "@tanstack/react-query";
import { useOutletContext } from "react-router";
import { api } from "../../api";
import type { LightboxImage } from "../../components/ui";
import type { Engagement, Evidence, Finding, Target } from "../../types";

export interface EngagementCtx {
  engagement: Engagement;
  base: string; // API base path for this engagement
}

export const useEngagement = () => useOutletContext<EngagementCtx>();

// Shared queries so every tab hits the same cache entries.
export function useTargets(base: string) {
  return useQuery({ queryKey: [base, "targets"], queryFn: () => api.get<Target[]>(`${base}/targets`) });
}

export function useFindings(base: string) {
  return useQuery({ queryKey: [base, "findings"], queryFn: () => api.get<Finding[]>(`${base}/findings`) });
}

// ----------------------------------------------------------------- evidence

export const evidenceUrl = (base: string, e: Evidence, inline = false) =>
  `${base}/evidence/${e.id}/download${inline ? "?inline=true" : ""}`;

export interface EvidenceLinks {
  description?: string;
  finding_id?: number | string;
  target_id?: number | string;
}

/** Upload files one by one as raw bodies (streamed into the vault, never spooled to a plaintext temp file). */
export async function uploadEvidence(base: string, files: FileList | File[], links: EvidenceLinks = {}) {
  for (const file of Array.from(files)) {
    await api.upload<Evidence>(`${base}/evidence/upload`, file, { ...links });
  }
  return files.length;
}

/** Lightbox entries for the image evidence in `items`. */
export function evidenceImages(base: string, items: Evidence[]): LightboxImage[] {
  return items
    .filter((e) => e.is_image)
    .map((e) => ({
      src: evidenceUrl(base, e, true),
      title: e.filename,
      caption: e.description || undefined,
      href: evidenceUrl(base, e),
    }));
}

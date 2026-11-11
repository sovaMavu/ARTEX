// How a launched task is described to the backend.
//
// The prompt text itself is NOT defined here any more: it lives in editable
// templates (lib/launcher/template-text.ts + the Templates page). This module only
// knows the shape of a launch, so the scheduler and the editor can share it.

import type { TemplateValues } from "./template-text";

export type ScannerProfile = "quick" | "standard" | "deep";

export const PROFILE_LABELS: Record<ScannerProfile, string> = {
  quick: "Quick",
  standard: "Standard",
  deep: "Deep",
};

export const PROFILE_HINTS: Record<ScannerProfile, string> = {
  quick: "Recon plus the obvious checks. ~30–60 min.",
  standard: "Full external surface, plan first. ~2–4 h.",
  deep: "Standard plus chained escalation on confirmed findings. ~8 h.",
};

/** A launch: the target values plus the template rendered against them. */
export interface LaunchPlan extends TemplateValues {
  taskName: string;
  description: string;
  goal: string;
  timeoutSeconds: number;
  seedFirstIntent: boolean;
  blockIpTargets: boolean;
}

/** Task name shown in the list; the domain, so runs stay sortable and scannable. */
export function buildTaskName(values: TemplateValues): string {
  return values.domain;
}

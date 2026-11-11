// Templates are plain text with placeholders. Rendering happens client-side at launch
// time, so a saved template stays reusable across targets — while the *created task*
// stores only the rendered text, so later edits never rewrite history.
//
// Only the validated target is ever substituted from operator input; everything else
// in a template is fixed text the operator wrote deliberately.

import type { ScannerProfile } from "./template";

/** The values a template can interpolate. */
export interface TemplateValues {
  /** Bare host, e.g. "example.com" or "10.0.0.5". */
  domain: string;
  /** Host with scheme, e.g. "https://example.com". */
  target: string;
  /** Extra authorised hosts (already normalised). */
  extraScope: string[];
  profile: ScannerProfile;
}

export const PLACEHOLDERS = {
  domain: "{domain}",
  target: "{target}",
  scope: "{scope}",
  profile: "{profile}",
} as const;

/** Descriptions for the placeholder help panel. */
export const PLACEHOLDER_HELP: { token: string; label: string }[] = [
  { token: PLACEHOLDERS.domain, label: "Bare host, no scheme (example.com)" },
  { token: PLACEHOLDERS.target, label: "Host with scheme (https://example.com)" },
  { token: PLACEHOLDERS.scope, label: "Extra in-scope hosts, comma separated (may be empty)" },
  { token: PLACEHOLDERS.profile, label: "Selected depth (quick / standard / deep)" },
];

/**
 * renderTemplate substitutes placeholders in one pass. A single pass on purpose: a
 * replacement that itself contains "{domain}" must not be substituted again, or a
 * crafted host name could inject text into the goal sent to the planner.
 */
export function renderTemplate(text: string, v: TemplateValues): string {
  const scope = v.extraScope.filter(Boolean).join(", ");
  const map: Record<string, string> = {
    [PLACEHOLDERS.domain]: v.domain,
    [PLACEHOLDERS.target]: v.target,
    [PLACEHOLDERS.scope]: scope,
    [PLACEHOLDERS.profile]: v.profile,
  };
  return text.replace(/\{(domain|target|scope|profile)\}/g, (token) => map[token] ?? token);
}

/** unknownPlaceholders lists {tokens} in text that this renderer cannot fill. */
export function unknownPlaceholders(text: string): string[] {
  const known = new Set<string>(Object.values(PLACEHOLDERS));
  const found = new Set<string>();
  for (const m of text.matchAll(/\{[a-zA-Z_]+\}/g)) {
    if (!known.has(m[0])) found.add(m[0]);
  }
  return [...found];
}

/**
 * The goal gate (server/goal_gate.go) mirrors. Used for live feedback in the editor
 * so an operator cannot save a template that every launch will reject.
 */
export const GOAL_MIN_LEN = 80;
const TARGET_PATTERNS = [
  /\bhttps?:\/\/\S+/i,
  /\b[a-z0-9][a-z0-9-]{1,61}\.[a-z]{2,}(:[0-9]+)?(\/\S*)?\b/i,
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b/,
  /\blocalhost:[0-9]+\b/i,
  /(^|\s)\/[a-z0-9_-]+(\/[a-z0-9_.-]+)+/i,
];

/**
 * goalGateProblems returns the reasons the backend would reject this goal.
 *
 * This runs on the SOURCE text, before rendering, which matters: the template's own
 * sentence names no host ("...of {target} and its subdomains..."), so the domain
 * regex has nothing to match until {target} is substituted. Checking the rendered
 * preview (or the source without this substitution) would flag every good template.
 * Treating a target placeholder as satisfying the pattern mirrors what the backend
 * will see at launch.
 */
export function goalGateProblems(goal: string): string[] {
  const g = goal.trim();
  const problems: string[] = [];
  if (!g) return ["The goal is empty."];
  if (/\[targetless\]/.test(g)) return problems;
  if (g.length < GOAL_MIN_LEN) {
    problems.push(`The goal must be at least ${GOAL_MIN_LEN} characters (currently ${g.length}).`);
  }
  // A placeholder renders to a host (or an IP), so it satisfies the gate at launch.
  const withTarget = g
    .split(PLACEHOLDERS.target)
    .join("https://place-holder.example")
    .split(PLACEHOLDERS.domain)
    .join("place-holder.example");
  if (!TARGET_PATTERNS.some((re) => re.test(withTarget))) {
    problems.push("The goal must name a target. Include {target} or {domain}.");
  }
  return problems;
}

/** Whether a template goal depends on the launch target at all. */
export function goalUsesTarget(goal: string): boolean {
  return goal.includes(PLACEHOLDERS.target) || goal.includes(PLACEHOLDERS.domain);
}

// Sample values for the live preview inside the editor.
export const PREVIEW_VALUES: TemplateValues = {
  domain: "example.com",
  target: "https://example.com",
  extraScope: ["api.example.com"],
  profile: "standard",
};

export interface StarterTemplate {
  name: string;
  description: string;
  goal: string;
  profile: ScannerProfile;
  timeoutSeconds: number;
  seedFirstIntent: boolean;
  blockIpTargets: boolean;
}

/** The factory template: what the launcher used before templates were editable. */
export const DEFAULT_TEMPLATE: StarterTemplate = {
  name: "External web assessment",
  description: "External security assessment of {domain}",
  goal:
    "Perform an authorized, non-destructive external penetration test of {target} and its subdomains. " +
    "Treat only {target} and hosts that resolve to its registered domain as in scope. " +
    "Start with passive and active reconnaissance, map the reachable attack surface, " +
    "then validate the findings that matter: authentication and authorization flaws, injection, " +
    "misconfiguration, exposed secrets and sensitive files, outdated or vulnerable components, " +
    "and missing security headers or transport protections. " +
    "Record every finding with reproducible evidence (request, response, impact), " +
    "never modify or destroy data, and stop escalating as soon as impact is demonstrated.",
  profile: "standard",
  timeoutSeconds: 4 * 3600,
  seedFirstIntent: false,
  blockIpTargets: true,
};

export const TEMPLATE_TIMEOUT_MAX = 48 * 3600;

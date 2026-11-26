"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter } from "next/navigation";

import { Play, Settings2 } from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { api } from "@/lib/api";
import { normalizeInput, parseHostList } from "@/lib/launcher/normalize";
import {
  buildTaskName,
  type LaunchPlan,
  PROFILE_HINTS,
  PROFILE_LABELS,
  type ScannerProfile,
} from "@/lib/launcher/template";
import { DEFAULT_TEMPLATE, goalGateProblems, renderTemplate, type TemplateValues } from "@/lib/launcher/template-text";
import type { AssetInterceptRuleInput, TaskTemplate } from "@/lib/types";

import { GoalPreview } from "./goal-preview";

/** The IP-target block rule; mirrored by the Templates editor toggle. */
const IP_TARGET_RULE: AssetInterceptRuleInput = {
  enabled: true,
  action: "block",
  kind: "cidr",
  pattern: "0.0.0.0/0",
  note: "launcher: bare IP-range targets are out of scope",
};

const FACTORY_ID = 0;

interface Chosen {
  id: number;
  name: string;
  description: string;
  goal: string;
  profile: ScannerProfile;
  timeoutSeconds: number;
  seedFirstIntent: boolean;
  blockIpTargets: boolean;
  interceptRules: AssetInterceptRuleInput[];
}

function fromTemplate(t: TaskTemplate): Chosen {
  return {
    id: t.id,
    name: t.name,
    description: t.description,
    goal: t.goal,
    profile: (t.scanner_profile as ScannerProfile | null | undefined) ?? "standard",
    timeoutSeconds: t.timeout_seconds ?? 0,
    seedFirstIntent: Boolean(t.seed_first_intent),
    // Templates created elsewhere carry no opinion; the IP guard stays on by default.
    blockIpTargets: t.block_ip_targets ?? true,
    interceptRules: (t.intercept_rules ?? []).filter((r) => r.pattern),
  };
}

function fromFactory(): Chosen {
  return {
    id: FACTORY_ID,
    name: DEFAULT_TEMPLATE.name,
    description: DEFAULT_TEMPLATE.description,
    goal: DEFAULT_TEMPLATE.goal,
    profile: DEFAULT_TEMPLATE.profile,
    timeoutSeconds: DEFAULT_TEMPLATE.timeoutSeconds,
    seedFirstIntent: DEFAULT_TEMPLATE.seedFirstIntent,
    blockIpTargets: DEFAULT_TEMPLATE.blockIpTargets,
    interceptRules: [],
  };
}

export function LauncherForm({ llmReady }: { llmReady: boolean }) {
  const router = useRouter();
  const [raw, setRaw] = React.useState("");
  const [extraRaw, setExtraRaw] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState("");

  const [templates, setTemplates] = React.useState<TaskTemplate[]>([]);
  const [chosen, setChosen] = React.useState<Chosen>(fromFactory);
  const [profileOverride, setProfileOverride] = React.useState<ScannerProfile | null>(null);

  React.useEffect(() => {
    api
      .taskTemplates()
      .then((list) => {
        setTemplates(list);
        if (list[0]) setChosen(fromTemplate(list[0]));
      })
      .catch(() => setTemplates([])); // fall back to the factory template, never block the launch
  }, []);

  // Live validation: the operator sees the resolved target before committing.
  const parsed = React.useMemo(() => (raw.trim() ? normalizeInput(raw) : null), [raw]);
  const extras = React.useMemo(() => parseHostList(extraRaw), [extraRaw]);

  const profile = profileOverride ?? chosen.profile;

  const values: TemplateValues | null = parsed?.ok
    ? { domain: parsed.domain, target: parsed.target, extraScope: extras.hosts, profile }
    : null;

  const plan: LaunchPlan | null = values
    ? {
        ...values,
        taskName: buildTaskName(values),
        description: renderTemplate(chosen.description || DEFAULT_TEMPLATE.description, values).trim(),
        goal: renderTemplate(chosen.goal, values).trim(),
        timeoutSeconds: chosen.timeoutSeconds,
        seedFirstIntent: chosen.seedFirstIntent,
        blockIpTargets: chosen.blockIpTargets,
      }
    : null;

  // The goal gate is the backend's rule; checking it here means a template that can
  // never launch is caught before the operator waits for a 400.
  const gateProblems = plan ? goalGateProblems(plan.goal) : [];

  const canStart = Boolean(plan) && !submitting && extras.errors.length === 0 && gateProblems.length === 0;

  const disabledReason = (() => {
    if (!llmReady) return "Configure an LLM profile first.";
    if (!plan) return "Enter a valid target.";
    if (extras.errors.length > 0) return "Fix the extra in-scope hosts.";
    if (gateProblems.length > 0) return "The selected template's prompt fails the goal gate.";
    return "";
  })();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!plan || !canStart) return;
    setSubmitting(true);
    setError("");
    try {
      const task = await api.createTask({
        name: plan.taskName,
        description: plan.description,
        goal: plan.goal,
        timeoutSeconds: plan.timeoutSeconds,
        seedFirstIntent: plan.seedFirstIntent,
        coverageEnabled: true,
        interceptRules: chosen.blockIpTargets ? [IP_TARGET_RULE, ...chosen.interceptRules] : chosen.interceptRules,
      });

      // Record the confirmed scope explicitly. The engine also auto-adds rows, but
      // this one carries who authorized it and when — the audit trail that makes
      // a run defensible afterwards.
      const stamp = new Date().toISOString();
      await api.addTaskScope(task.id, "root_domain", plan.domain, `authorized by operator via launcher at ${stamp}`);
      for (const host of extras.hosts) {
        await api.addTaskScope(task.id, "subdomain", host, `authorized scope (listed at launch, ${stamp})`);
      }

      toast.success(`Assessment started for ${plan.domain}`);
      router.push(`/function/tasks/detail?id=${encodeURIComponent(task.id)}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      toast.error("Could not start the assessment", { description: message });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="space-y-2">
        <Label htmlFor="launcher-target">Target</Label>
        <Input
          id="launcher-target"
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          placeholder="example.com"
          autoComplete="off"
          spellCheck={false}
          className="h-10 font-mono text-base"
          aria-invalid={parsed?.ok === false}
          disabled={submitting}
        />
        {parsed?.ok === false && <p className="text-destructive text-xs">{parsed.error}</p>}
        {parsed?.ok &&
          parsed.warnings.map((w) => (
            <p key={w} className="text-amber-600 text-xs dark:text-amber-400">
              {w}
            </p>
          ))}
        {parsed?.ok && (
          <p className="text-muted-foreground text-xs">
            Will be scanned as <span className="font-mono">{parsed.target}</span>
          </p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="launcher-extra">Additional in-scope hosts (optional)</Label>
        <Textarea
          id="launcher-extra"
          value={extraRaw}
          onChange={(e) => setExtraRaw(e.target.value)}
          placeholder="api.example.com, admin.example.com"
          spellCheck={false}
          className="min-h-16 font-mono"
          disabled={submitting}
        />
        {extras.errors.length > 0 && (
          <ul className="text-destructive text-xs">
            {extras.errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}
      </div>

      <div className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <Label htmlFor="launcher-template">Template</Label>
          <Button asChild variant="ghost" size="sm">
            <Link href="/templates" prefetch={false}>
              <Settings2 />
              Manage templates
            </Link>
          </Button>
        </div>
        <NativeSelect
          id="launcher-template"
          className="w-full"
          value={String(chosen.id)}
          onChange={(e) => {
            const id = Number(e.target.value);
            const t = templates.find((x) => x.id === id);
            setChosen(t ? fromTemplate(t) : fromFactory());
            setProfileOverride(null); // the template brings its own default depth
          }}
          disabled={submitting}
        >
          {templates.length > 0 && (
            <optgroup label="Saved templates">
              {templates.map((t) => (
                <NativeSelectOption key={t.id} value={String(t.id)}>
                  {t.name}
                </NativeSelectOption>
              ))}
            </optgroup>
          )}
          <optgroup label="Factory">
            <NativeSelectOption value={String(FACTORY_ID)}>{DEFAULT_TEMPLATE.name}</NativeSelectOption>
          </optgroup>
        </NativeSelect>
        <p className="text-muted-foreground text-xs">
          Sets the prompt sent to the planner.{" "}
          <Link href="/templates" prefetch={false} className="underline underline-offset-2">
            Edit or add your own
          </Link>
          .
        </p>
      </div>

      <div className="space-y-2">
        <Label>Depth</Label>
        <ToggleGroup
          type="single"
          variant="outline"
          value={profile}
          onValueChange={(v) => v && setProfileOverride(v as ScannerProfile)}
          className="w-full justify-start"
          disabled={submitting}
        >
          {(Object.keys(PROFILE_LABELS) as ScannerProfile[]).map((key) => (
            <ToggleGroupItem key={key} value={key} className="px-3">
              {PROFILE_LABELS[key]}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        <p className="text-muted-foreground text-xs">{PROFILE_HINTS[profile]}</p>
      </div>

      {plan && <GoalPreview plan={plan} gateProblems={gateProblems} templateName={chosen.name} />}

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={!canStart} className="min-w-40">
          {submitting ? <Spinner /> : <Play />}
          {submitting ? "Starting…" : "Start assessment"}
        </Button>
        {disabledReason && !submitting && <span className="text-muted-foreground text-xs">{disabledReason}</span>}
      </div>
    </form>
  );
}

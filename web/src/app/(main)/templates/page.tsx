"use client";

import * as React from "react";

import { AlertTriangle, CopyIcon, PlusIcon, SaveIcon, SparklesIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { AssetInterceptRulesEditor } from "@/components/asset-intercept-rules-editor";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { PROFILE_HINTS, PROFILE_LABELS, type ScannerProfile } from "@/lib/launcher/template";
import {
  DEFAULT_TEMPLATE,
  goalGateProblems,
  goalUsesTarget,
  PLACEHOLDER_HELP,
  PLACEHOLDERS,
  PREVIEW_VALUES,
  renderTemplate,
  type StarterTemplate,
  TEMPLATE_TIMEOUT_MAX,
  unknownPlaceholders,
} from "@/lib/launcher/template-text";
import type { AssetInterceptRuleInput, TaskTemplate } from "@/lib/types";
import { cn } from "@/lib/utils";

/** The launcher's block rule, kept in one place so the editor and the launch agree. */
export const IP_TARGET_RULE: AssetInterceptRuleInput = {
  enabled: true,
  action: "block",
  kind: "cidr",
  pattern: "0.0.0.0/0",
  note: "launcher: bare IP-range targets are out of scope",
};

interface Draft {
  id: number | null;
  name: string;
  description: string;
  goal: string;
  profile: ScannerProfile;
  /** hours; 0 = no limit */
  timeoutHours: number;
  seedFirstIntent: boolean;
  blockIpTargets: boolean;
  interceptRules: AssetInterceptRuleInput[];
}

function draftFromTemplate(t: TaskTemplate): Draft {
  return {
    id: t.id,
    name: t.name,
    description: t.description,
    goal: t.goal,
    profile: (t.scanner_profile as ScannerProfile | null | undefined) ?? "standard",
    timeoutHours: t.timeout_seconds ? Math.round(t.timeout_seconds / 3600) : 0,
    seedFirstIntent: Boolean(t.seed_first_intent),
    blockIpTargets: t.block_ip_targets ?? true,
    interceptRules: (t.intercept_rules ?? []).filter((r) => r.pattern),
  };
}

function draftFromStarter(s: StarterTemplate): Draft {
  return {
    id: null,
    name: s.name,
    description: s.description,
    goal: s.goal,
    profile: s.profile,
    timeoutHours: Math.round(s.timeoutSeconds / 3600),
    seedFirstIntent: s.seedFirstIntent,
    blockIpTargets: s.blockIpTargets,
    interceptRules: [],
  };
}

// rulesForSend merges the IP-target toggle into the operator's own rules. The toggle
// is a convenience over one specific rule, not a separate concept, so editing the
// rule by hand has to win over it rather than duplicate it.
function rulesForSend(d: Draft): AssetInterceptRuleInput[] {
  const own = d.interceptRules
    .map((r) => ({ ...r, pattern: r.pattern.trim() }))
    .filter((r) => r.pattern !== "")
    .filter((r) => !(d.blockIpTargets && r.kind === "cidr" && r.pattern === IP_TARGET_RULE.pattern));
  return d.blockIpTargets ? [IP_TARGET_RULE, ...own] : own;
}

export default function TemplatesPage() {
  const [templates, setTemplates] = React.useState<TaskTemplate[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [draft, setDraft] = React.useState<Draft>(() => draftFromStarter(DEFAULT_TEMPLATE));
  const [saving, setSaving] = React.useState(false);
  const [deleteOpen, setDeleteOpen] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.taskTemplates();
      setTemplates(list);
      // Open the first template if one exists, otherwise stay on the starter.
      setDraft((current) => (current.id == null && list[0] ? draftFromTemplate(list[0]) : current));
    } catch (e) {
      toast.error(`Failed to load templates: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));

  const goalProblems = goalGateProblems(draft.goal);
  const unknown = React.useMemo(
    () => [...new Set([...unknownPlaceholders(draft.goal), ...unknownPlaceholders(draft.description)])],
    [draft.goal, draft.description],
  );
  const missingTarget = draft.goal.trim() !== "" && !goalUsesTarget(draft.goal);
  const canSave = draft.name.trim() !== "" && draft.goal.trim() !== "" && goalProblems.length === 0 && !saving;

  function insertPlaceholder(token: string) {
    const el = document.getElementById("tpl-goal") as HTMLTextAreaElement | null;
    const text = draft.goal;
    if (!el) {
      set({ goal: text + token });
      return;
    }
    const start = el.selectionStart ?? text.length;
    const end = el.selectionEnd ?? text.length;
    set({ goal: text.slice(0, start) + token + text.slice(end) });
    requestAnimationFrame(() => {
      el.focus();
      el.setSelectionRange(start + token.length, start + token.length);
    });
  }

  async function save(asCopy: boolean) {
    const body = {
      name: draft.name.trim(),
      description: draft.description.trim() || `External security assessment of ${PLACEHOLDERS.domain}`,
      goal: draft.goal.trim(),
      scanner_profile: draft.profile,
      timeout_seconds: draft.timeoutHours > 0 ? draft.timeoutHours * 3600 : 0,
      seed_first_intent: draft.seedFirstIntent,
      block_ip_targets: draft.blockIpTargets,
      intercept_rules: rulesForSend(draft),
    };
    setSaving(true);
    try {
      if (draft.id != null && !asCopy) {
        const updated = await api.updateTaskTemplate(draft.id, body);
        setTemplates((list) => [updated, ...list.filter((t) => t.id !== updated.id)]);
        setDraft(draftFromTemplate(updated));
        toast.success("Template saved");
      } else {
        const name = asCopy ? `${body.name} (copy)`.slice(0, 120) : body.name;
        const created = await api.createTaskTemplate({ ...body, name });
        setTemplates((list) => [created, ...list]);
        setDraft(draftFromTemplate(created));
        toast.success(asCopy ? "Template duplicated" : "Template created");
      }
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    if (draft.id == null) return;
    const id = draft.id;
    try {
      await api.deleteTaskTemplate(id);
      const rest = templates.filter((t) => t.id !== id);
      setTemplates(rest);
      setDraft(rest[0] ? draftFromTemplate(rest[0]) : draftFromStarter(DEFAULT_TEMPLATE));
      setDeleteOpen(false);
      toast.success("Template deleted");
    } catch (e) {
      toast.error(`Delete failed: ${(e as Error).message}`);
    }
  }

  const isNew = draft.id == null;

  return (
    <div className="grid min-h-0 gap-4 lg:h-[calc(100dvh-6rem)] lg:grid-cols-[17rem_minmax(0,1fr)]">
      {/* List */}
      <aside className="flex min-h-0 flex-col rounded-xl border">
        <div className="flex flex-col gap-2 border-b p-3">
          <Button variant="outline" className="w-full" onClick={() => setDraft(draftFromStarter(DEFAULT_TEMPLATE))}>
            <PlusIcon />
            New template
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start"
            onClick={() => setDraft(draftFromStarter(DEFAULT_TEMPLATE))}
          >
            <SparklesIcon />
            Restore factory default
          </Button>
        </div>
        <ScrollArea className="min-h-0 flex-1">
          <div className="flex flex-col gap-1 p-2">
            {loading && <p className="px-2 py-6 text-center text-muted-foreground text-sm">Loading…</p>}
            {!loading && templates.length === 0 && (
              <p className="px-2 py-6 text-center text-muted-foreground text-sm">
                No saved templates yet. The factory default is open on the right — save it to start editing.
              </p>
            )}
            {templates.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setDraft(draftFromTemplate(t))}
                className={cn(
                  "rounded-md px-2.5 py-2 text-left transition-colors",
                  draft.id === t.id ? "bg-accent text-accent-foreground" : "hover:bg-accent/50",
                )}
              >
                <span className="block truncate font-medium text-sm">{t.name}</span>
                <span className="block truncate text-muted-foreground text-xs">{t.description}</span>
              </button>
            ))}
          </div>
        </ScrollArea>
      </aside>

      {/* Editor */}
      <section className="flex min-h-0 flex-col rounded-xl border">
        <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
          <div className="min-w-0 flex-1">
            <h1 className="truncate font-heading text-lg font-semibold">
              {isNew ? "New template" : draft.name || "Untitled template"}
            </h1>
            <p className="text-muted-foreground text-xs">
              {isNew ? "Not saved yet" : "Edits apply to future launches; tasks already created keep their text."}
            </p>
          </div>
          <Button variant="outline" size="sm" disabled={saving} onClick={() => void save(!isNew)}>
            {!isNew && <CopyIcon />}
            {isNew ? "Save" : "Duplicate"}
          </Button>
          <Button size="sm" disabled={!canSave} onClick={() => void save(false)}>
            {saving ? <Spinner /> : <SaveIcon />}
            {isNew ? "Create template" : "Save changes"}
          </Button>
          {!isNew && (
            <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}>
              <Trash2Icon />
              Delete
            </Button>
          )}
        </div>

        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-5 p-4">
            <div className="space-y-1.5">
              <label htmlFor="tpl-name" className="text-sm font-medium">
                Name
              </label>
              <Input
                id="tpl-name"
                value={draft.name}
                maxLength={120}
                placeholder="e.g. Quick external check"
                onChange={(e) => set({ name: e.target.value })}
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="tpl-description" className="text-sm font-medium">
                Description
              </label>
              <Input
                id="tpl-description"
                value={draft.description}
                placeholder={`External security assessment of ${PLACEHOLDERS.domain}`}
                onChange={(e) => set({ description: e.target.value })}
              />
              <p className="text-muted-foreground text-xs">Shown as the task subtitle. Use {PLACEHOLDERS.domain}.</p>
            </div>

            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label htmlFor="tpl-goal" className="text-sm font-medium">
                  Prompt — the goal sent to the planner
                </label>
                <div className="flex flex-wrap gap-1">
                  {PLACEHOLDER_HELP.map((p) => (
                    <Button
                      key={p.token}
                      type="button"
                      variant="outline"
                      size="xs"
                      title={p.label}
                      onClick={() => insertPlaceholder(p.token)}
                    >
                      <code className="font-mono">{p.token}</code>
                    </Button>
                  ))}
                </div>
              </div>
              <Textarea
                id="tpl-goal"
                value={draft.goal}
                onChange={(e) => set({ goal: e.target.value })}
                className="min-h-56 font-mono text-[13px] leading-relaxed"
                spellCheck={false}
              />
              <p className="text-muted-foreground text-xs">
                {draft.goal.trim().length} characters · minimum 80 · insert a placeholder by clicking it, it lands at
                the cursor.
              </p>

              {goalProblems.length > 0 && (
                <Alert variant="destructive">
                  <AlertTriangle />
                  <AlertDescription>
                    <ul className="list-inside list-disc">
                      {goalProblems.map((p) => (
                        <li key={p}>{p}</li>
                      ))}
                    </ul>
                  </AlertDescription>
                </Alert>
              )}
              {unknown.length > 0 && (
                <Alert>
                  <AlertTriangle />
                  <AlertDescription>
                    Unknown placeholders will be sent literally: <span className="font-mono">{unknown.join(", ")}</span>
                  </AlertDescription>
                </Alert>
              )}
              {missingTarget && (
                <Alert>
                  <AlertTriangle />
                  <AlertDescription>
                    This prompt does not reference <code className="font-mono">{PLACEHOLDERS.target}</code>. The goal
                    gate accepts it only if it names a target some other way, and the engine may seed the wrong asset.
                  </AlertDescription>
                </Alert>
              )}
            </div>

            <div className="space-y-1.5">
              <div className="text-sm font-medium">Preview</div>
              <pre className="max-h-52 overflow-auto rounded-md bg-muted/50 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap">
                {renderTemplate(draft.goal, PREVIEW_VALUES)}
              </pre>
              <p className="text-muted-foreground text-xs">
                Rendered for a sample target ({PREVIEW_VALUES.target}). The real run substitutes the operator's input.
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-3">
              <div className="space-y-1.5">
                <label htmlFor="tpl-profile" className="text-sm font-medium">
                  Default depth
                </label>
                <select
                  id="tpl-profile"
                  className="h-8 w-full rounded-lg border border-input bg-transparent px-2 text-sm"
                  value={draft.profile}
                  onChange={(e) => set({ profile: e.target.value as ScannerProfile })}
                >
                  {(Object.keys(PROFILE_LABELS) as ScannerProfile[]).map((p) => (
                    <option key={p} value={p}>
                      {PROFILE_LABELS[p]}
                    </option>
                  ))}
                </select>
                <p className="text-muted-foreground text-xs">{PROFILE_HINTS[draft.profile]}</p>
              </div>
              <div className="space-y-1.5">
                <label htmlFor="tpl-timeout" className="text-sm font-medium">
                  Time limit (hours)
                </label>
                <Input
                  id="tpl-timeout"
                  type="number"
                  min={0}
                  max={TEMPLATE_TIMEOUT_MAX / 3600}
                  value={draft.timeoutHours}
                  onChange={(e) => set({ timeoutHours: Math.max(0, Number(e.target.value) || 0) })}
                />
                <p className="text-muted-foreground text-xs">0 = no wall-clock limit.</p>
              </div>
              <div className="space-y-3">
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={draft.seedFirstIntent}
                    onChange={(e) => set({ seedFirstIntent: e.target.checked })}
                  />
                  <span>
                    Start a worker immediately
                    <span className="block text-muted-foreground text-xs">
                      Skips the first planning round; good for short runs.
                    </span>
                  </span>
                </label>
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={draft.blockIpTargets}
                    onChange={(e) => set({ blockIpTargets: e.target.checked })}
                  />
                  <span>
                    Block IP-range targets
                    <span className="block text-muted-foreground text-xs">
                      Adds a <code className="font-mono">0.0.0.0/0</code> block rule to launched tasks.
                    </span>
                  </span>
                </label>
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="text-sm font-medium">Additional intercept / allow rules</div>
              <AssetInterceptRulesEditor
                value={draft.interceptRules}
                onChange={(rules) => set({ interceptRules: rules })}
              />
              <p className="text-muted-foreground text-xs">
                Applied to tasks launched from this template. An invalid pattern makes the launch fail with 400, so test
                it here by saving.
              </p>
            </div>
          </div>
        </ScrollArea>
      </section>

      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete "{draft.name || "Untitled"}"?</AlertDialogTitle>
            <AlertDialogDescription>
              Tasks already created from this template are not affected. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => void remove()}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

"use client";

import { AlertTriangle, ChevronRight } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import type { LaunchPlan } from "@/lib/launcher/template";
import { GOAL_MIN_LEN } from "@/lib/launcher/template-text";

/**
 * Shows exactly what will be sent, rendered against the current target. The operator
 * sees the prompt before it is dispatched — which is the point of a template: it is
 * readable, fixed, and the only variable is the validated target.
 */
export function GoalPreview({
  plan,
  gateProblems,
  templateName,
}: {
  plan: LaunchPlan;
  gateProblems: string[];
  templateName: string;
}) {
  return (
    <Collapsible className="rounded-lg border">
      <CollapsibleTrigger className="group flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-muted/50">
        <ChevronRight className="size-4 shrink-0 text-muted-foreground transition-transform group-data-[state=open]:rotate-90" />
        <span className="font-medium">Prompt preview</span>
        <span className="truncate text-muted-foreground text-xs">
          {templateName} · {plan.goal.length} characters
        </span>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="space-y-3 border-t px-3 py-3">
          <Field label="Task name" value={plan.taskName} />
          <Field label="Description" value={plan.description} />
          <Field label="Goal (sent to the planner)" value={plan.goal} />
          {gateProblems.length > 0 ? (
            <Alert variant="destructive">
              <AlertTriangle />
              <AlertDescription>
                <ul className="list-inside list-disc">
                  {gateProblems.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
                <p className="mt-1">
                  The backend rejects this goal. Fix the prompt under Templates — it must be at least {GOAL_MIN_LEN}{" "}
                  characters and name a target.
                </p>
              </AlertDescription>
            </Alert>
          ) : (
            <p className="text-muted-foreground text-xs">
              Passes the backend goal gate ({GOAL_MIN_LEN}+ characters, names a target), so workers cannot be dispatched
              against an unrelated asset.
            </p>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <div className="text-muted-foreground text-xs font-medium">{label}</div>
      <pre className="max-h-40 overflow-auto rounded-md bg-muted/50 p-2 font-mono text-xs leading-relaxed whitespace-pre-wrap">
        {value}
      </pre>
    </div>
  );
}

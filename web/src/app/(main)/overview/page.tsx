"use client";

import * as React from "react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";

import { LauncherForm } from "./_components/launcher-form";
import { NoLlmBanner } from "./_components/no-llm-banner";
import { RecentRuns } from "./_components/recent-runs";

export default function OverviewPage() {
  // null = still checking. The launcher stays usable-but-disabled until the backend
  // answers, so a slow API never looks like a dead button.
  const [llmReady, setLlmReady] = React.useState<boolean | null>(null);
  const [checkError, setCheckError] = React.useState("");

  React.useEffect(() => {
    let alive = true;
    api
      .stats()
      .then((s) => alive && setLlmReady(Boolean(s.llm_configured)))
      .catch((e) => {
        if (!alive) return;
        setCheckError(e instanceof Error ? e.message : String(e));
        setLlmReady(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div className="mx-auto w-full max-w-3xl space-y-8 pb-16">
      <div className="space-y-1">
        <h1 className="font-heading text-2xl font-semibold tracking-tight">New assessment</h1>
        <p className="text-muted-foreground text-sm">
          Enter a domain. ARTEX plans the test, runs it against the target, and records findings with evidence.
        </p>
      </div>

      {checkError && <p className="text-destructive text-sm">Cannot reach the backend: {checkError}</p>}
      {llmReady === false && !checkError && <NoLlmBanner />}

      <Card>
        <CardHeader>
          <CardTitle>Target</CardTitle>
          <CardDescription>
            Only systems you own or have written permission to test. A run is recorded against the task's scope.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <LauncherForm llmReady={llmReady === true} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent runs</CardTitle>
        </CardHeader>
        <CardContent>
          <RecentRuns />
        </CardContent>
      </Card>
    </div>
  );
}

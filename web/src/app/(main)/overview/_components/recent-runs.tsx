"use client";

import * as React from "react";

import Link from "next/link";

import { StatusBadge } from "@/components/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { Task } from "@/lib/types";

/**
 * The last few runs, refreshed while anything is in flight. This is the only
 * "history" on the launcher — anything deeper lives on the task page.
 */
export function RecentRuns() {
  const [tasks, setTasks] = React.useState<Task[] | null>(null);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    let alive = true;
    let busy = false;
    const load = async () => {
      if (busy) return;
      busy = true;
      try {
        const r = await api.tasks();
        if (!alive) return;
        const sorted = [...r.tasks].sort((a, b) => (b.created_unix ?? 0) - (a.created_unix ?? 0)).slice(0, 8);
        setTasks(sorted);
        setError("");
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      } finally {
        busy = false;
      }
    };
    void load();
    const timer = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  if (tasks === null) {
    return <div className="text-muted-foreground text-sm">{error || "Loading recent runs…"}</div>;
  }
  if (tasks.length === 0) {
    return <div className="text-muted-foreground text-sm">No assessments yet. The first one starts above.</div>;
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Target</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Findings</TableHead>
          <TableHead className="text-right">Goals</TableHead>
          <TableHead className="text-right">Tokens</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {tasks.map((t) => {
          const f = t.findings ?? { critical: 0, high: 0, medium: 0, low: 0 };
          const total = f.critical + f.high + f.medium + f.low;
          return (
            <TableRow key={t.id}>
              <TableCell className="max-w-64 truncate">
                <Link
                  prefetch={false}
                  href={`/function/tasks/detail?id=${encodeURIComponent(t.id)}`}
                  className="font-mono text-sm hover:underline"
                >
                  {t.name || t.description}
                </Link>
              </TableCell>
              <TableCell>
                <StatusBadge domain="task" value={t.queued && t.status === "created" ? "queued" : t.status} />
              </TableCell>
              <TableCell className="text-right tabular-nums">
                {total === 0 ? (
                  <span className="text-muted-foreground">—</span>
                ) : (
                  <span title={`critical ${f.critical} · high ${f.high} · medium ${f.medium} · low ${f.low}`}>
                    {f.critical > 0 && <span className="text-rose-600 dark:text-rose-400">{f.critical}c </span>}
                    {f.high > 0 && <span className="text-red-600 dark:text-red-400">{f.high}h </span>}
                    {f.medium > 0 && <span className="text-amber-600 dark:text-amber-400">{f.medium}m </span>}
                    {f.low > 0 && <span className="text-slate-500">{f.low}l</span>}
                  </span>
                )}
              </TableCell>
              <TableCell className="text-right tabular-nums">
                {t.goals_met ?? 0}/{t.goals_total ?? 0}
              </TableCell>
              <TableCell className="text-right tabular-nums">
                {((t.tokens?.input_tokens ?? 0) + (t.tokens?.output_tokens ?? 0)).toLocaleString()}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

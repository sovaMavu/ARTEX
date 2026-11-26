"use client";

import Link from "next/link";

import { AlertTriangle } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

/**
 * Creating a task with no LLM provider does not fail — it is created and sits idle
 * (`engine_ready: false`), which looks identical to a slow scan. Block the launcher
 * instead of letting the operator wait on a run that cannot start.
 */
export function NoLlmBanner() {
  return (
    <Alert variant="destructive">
      <AlertTriangle />
      <AlertTitle>No LLM provider is active</AlertTitle>
      <AlertDescription>
        <p>
          The engine cannot start a run without an active model profile. Configure one, then come back — nothing here
          will progress until it is set.
        </p>
        <Button asChild size="sm" variant="outline" className="mt-2">
          <Link href="/system/llm" prefetch={false}>
            Open LLM configuration
          </Link>
        </Button>
      </AlertDescription>
    </Alert>
  );
}

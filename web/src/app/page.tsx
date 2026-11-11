"use client";

import * as React from "react";

import { useRouter } from "next/navigation";

/**
 * "/" has no content of its own: a no-login deployment lands on the launcher.
 *
 * Client-side redirect rather than a server `redirect()`, because the app is built
 * with `output: "export"` (NEXT_EXPORT=1) where server redirects are not emitted.
 */
export default function RootPage() {
  const router = useRouter();
  React.useEffect(() => {
    router.replace("/overview");
  }, [router]);
  return (
    <div role="status" className="flex min-h-dvh items-center justify-center text-muted-foreground">
      Opening console…
    </div>
  );
}

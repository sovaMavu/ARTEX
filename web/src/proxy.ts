import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

/**
 * No route guard: password login is off by default.
 *
 * Authorization lives in the Go backend (server/auth_mode.go), which only serves the
 * API to loopback peers and rejects cross-origin writes. A cookie/token check here
 * would guard the static shell — which holds no data — while the API it talks to
 * does not care.
 */
export function proxy(_request: NextRequest) {
  return NextResponse.next();
}

export const config = {
  // Skip Next.js internals, API routes, the favicon, and static assets under public/.
  matcher: [
    "/((?!_next/static|_next/image|favicon\\.ico|api/|.*\\.(?:png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|otf)$).*)",
  ],
};

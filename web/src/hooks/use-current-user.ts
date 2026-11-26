"use client";

import { OPERATOR, type Operator } from "@/lib/operator";

/**
 * There is one operator and no login: the backend trusts loopback peers
 * (server/auth_mode.go). Kept as a hook so call sites kept their shape and a future
 * real auth layer only has to change this file.
 */
export function useCurrentUser(): Operator {
  return OPERATOR;
}

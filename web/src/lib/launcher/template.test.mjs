import { buildTaskName, PROFILE_HINTS, PROFILE_LABELS } from "./template.ts";
import assert from "node:assert/strict";
import test from "node:test";

// The prompt text itself is editable now; its rendering is covered in
// template-text.test.mjs. This file only covers the launch-shape helpers.

test("task name is the bare domain", () => {
  assert.equal(
    buildTaskName({ domain: "example.com", target: "https://example.com", extraScope: [], profile: "quick" }),
    "example.com",
  );
});

test("every depth has a label and a hint", () => {
  for (const profile of ["quick", "standard", "deep"]) {
    assert.ok(PROFILE_LABELS[profile].length > 0, `${profile} needs a label`);
    assert.ok(PROFILE_HINTS[profile].length > 0, `${profile} needs a hint`);
  }
});

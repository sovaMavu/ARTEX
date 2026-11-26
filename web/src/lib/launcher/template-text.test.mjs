import { normalizeInput } from "./normalize.ts";
import {
  DEFAULT_TEMPLATE,
  goalGateProblems,
  goalUsesTarget,
  renderTemplate,
  unknownPlaceholders,
} from "./template-text.ts";
import assert from "node:assert/strict";
import test from "node:test";

// Mirror of server/goal_gate.go. Kept in step with template-text.ts on purpose.
const goalMinLen = 80;
const goalURLRE = /\bhttps?:\/\/\S+/i;
const goalDomainRE = /\b[a-z0-9][a-z0-9-]{1,61}\.[a-z]{2,}(:[0-9]+)?(\/\S*)?\b/i;
const goalIPv4RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b/;

function backendAccepts(goal) {
  const g = goal.trim();
  if (/\[targetless\]/.test(g)) return true;
  if (g.length < goalMinLen) return false;
  return goalURLRE.test(g) || goalDomainRE.test(g) || goalIPv4RE.test(g);
}

const values = (raw) => {
  const n = normalizeInput(raw);
  assert.equal(n.ok, true);
  return { domain: n.domain, target: n.target, extraScope: [], profile: "standard" };
};

test("factory template renders to a goal the backend accepts, for every domain shape", () => {
  for (const domain of ["example.com", "a.co", "www.example.co.uk", "10.0.0.5", "203.0.113.200"]) {
    const v = values(domain);
    const goal = renderTemplate(DEFAULT_TEMPLATE.goal, v);
    assert.ok(goal.length >= goalMinLen, `${domain}: ${goal.length} chars`);
    assert.ok(backendAccepts(goal), `${domain}: goal would be rejected`);
    assert.ok(goal.includes(v.target), `${domain}: target must appear verbatim`);
    assert.deepEqual(goalGateProblems(goal), [], `${domain}: editor gate must agree`);
  }
});

test("placeholders are replaced in one pass only", () => {
  assert.equal(
    renderTemplate("{target} {domain}", { domain: "x.com", target: "https://x.com", extraScope: [], profile: "quick" }),
    "https://x.com x.com",
  );
  // A replacement containing a placeholder must not be substituted again.
  const evil = { domain: "{target}", target: "https://{domain}", extraScope: [], profile: "quick" };
  assert.equal(renderTemplate("{domain}", evil), "{target}");
});

test("scope renders comma separated and empty when absent", () => {
  const base = { domain: "x.com", target: "https://x.com", profile: "quick" };
  assert.equal(renderTemplate("[{scope}]", { ...base, extraScope: [] }), "[]");
  assert.equal(renderTemplate("[{scope}]", { ...base, extraScope: ["a.x.com", "b.x.com"] }), "[a.x.com, b.x.com]");
});

test("unknown placeholders are reported, not silently sent", () => {
  assert.deepEqual(unknownPlaceholders("scan {target} and {company}"), ["{company}"]);
  assert.deepEqual(unknownPlaceholders("{target} {domain} {scope} {profile}"), []);
});

test("the editor gate mirrors the backend gate", () => {
  assert.equal(goalGateProblems("").length, 1);
  assert.equal(goalGateProblems("too short").length, 2); // length + no target
  assert.equal(
    goalGateProblems("A long enough goal that names no host at all, just prose that goes on and on forever.").length,
    1,
  );
  assert.deepEqual(goalGateProblems(renderTemplate(DEFAULT_TEMPLATE.goal, values("example.com"))), []);
});

test("a template without a target placeholder is flagged", () => {
  assert.equal(goalUsesTarget(DEFAULT_TEMPLATE.goal), true);
  assert.equal(
    goalUsesTarget("Look at the target carefully and report anything that looks off, in detail please."),
    false,
  );
});

test("the factory template's SOURCE text passes the editor gate", () => {
  // Regression: the source names no host until {target} is substituted, so a gate
  // that ran on the raw text rejected the template everyone starts with.
  assert.deepEqual(goalGateProblems(DEFAULT_TEMPLATE.goal), []);
  // Prose with no target at all is still rejected.
  assert.equal(
    goalGateProblems("Please look at the system carefully and report anything that seems off, in as much detail as you can.")
      .length,
    1,
  );
});

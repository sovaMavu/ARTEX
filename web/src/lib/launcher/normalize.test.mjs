import { normalizeInput, parseHostList, registrableDomain } from "./normalize.ts";
import assert from "node:assert/strict";
import test from "node:test";

const ok = (raw) => {
  const r = normalizeInput(raw);
  assert.equal(r.ok, true, `${raw} should normalise, got: ${r.error}`);
  return r;
};
const bad = (raw) => {
  const r = normalizeInput(raw);
  assert.equal(r.ok, false, `${raw} should be rejected, got domain=${r.domain}`);
};

test("URLs reduce to the bare host", () => {
  assert.equal(ok("https://www.Example.COM/login?next=1#x").domain, "www.example.com");
  assert.equal(ok("http://example.com").domain, "example.com");
  assert.equal(ok("example.com:8443").domain, "example.com");
  assert.equal(ok("example.com.").domain, "example.com");
  assert.equal(ok("  example.com  ").domain, "example.com");
  assert.equal(ok("user:pass@example.com/path").domain, "example.com");
  assert.equal(ok("ftp://example.com").domain, "example.com");
});

test("names get an https target, bare IPs get http", () => {
  assert.equal(ok("example.com").target, "https://example.com");
  assert.equal(ok("10.0.0.5").target, "http://10.0.0.5");
  assert.equal(ok("10.0.0.5:8080").domain, "10.0.0.5");
});

test("subdomains warn but are accepted", () => {
  const r = ok("https://www.example.com");
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], /example\.com/);
  assert.equal(ok("example.com").warnings.length, 0);
});

test("junk is rejected", () => {
  for (const raw of [
    "",
    "   ",
    "not a domain",
    "localhost",
    "foo.local",
    "box.internal",
    "example",
    "300.1.1.1",
    "-bad.com",
  ]) {
    bad(raw);
  }
});

test("registrableDomain approximates eTLD+1", () => {
  assert.equal(registrableDomain("www.example.com"), "example.com");
  assert.equal(registrableDomain("example.com"), "example.com");
  assert.equal(registrableDomain("a.b.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("api.example.com"), "example.com");
});

test("parseHostList validates each entry independently", () => {
  // Entries are comma/space separated, so a multi-word typo becomes several bad
  // entries — each is rejected on its own, none sinks the valid ones.
  const { hosts, errors } = parseHostList("api.example.com, shop.example.com \n not_a_host\n10.0.0.5\napi.example.com");
  assert.deepEqual(hosts, ["api.example.com", "shop.example.com", "10.0.0.5"]);
  assert.equal(errors.length, 1);

  const multi = parseHostList("api.example.com not a host");
  assert.deepEqual(multi.hosts, ["api.example.com"]);
  assert.equal(multi.errors.length, 3, "each whitespace token is validated separately");
});

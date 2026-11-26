// Turns whatever an operator pastes ("https://www.example.com/x?y=1", "example.com:8443",
// "10.0.0.5") into the two values the backend actually needs:
//
//   domain — the bare host, used as the task name, the scope value and the asset key
//            (db.DomainKey). No scheme, no port, no trailing dot.
//   target — the same host with a scheme, for the prompt text. This MUST appear
//            verbatim in the goal: server/goal_gate.go rejects any goal that names
//            no URL/domain/IP, and server/server.go's seed() parses the target out of
//            description+goal to create the starting asset.
//
// Rejecting non-public hosts is deliberate: the engine runs nmap/sqlmap/shell inside
// the container, so "localhost" or a docker-internal name would aim it at the
// container's own network.

const HOST_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const LOCAL_SUFFIXES = [".local", ".internal", ".localhost", ".lan", ".home", ".corp"];

export type NormalizeResult =
  | { ok: true; domain: string; target: string; warnings: string[] }
  | { ok: false; error: string };

export function normalizeInput(raw: string): NormalizeResult {
  let s = raw.trim().toLowerCase();
  if (!s) return { ok: false, error: "Enter a domain, host name or IP address." };

  // Strip a scheme without trusting URL() to accept every malformed variant.
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  // Drop credentials, path, query, fragment.
  s = s.split(/[/?#]/)[0];
  // Drop userinfo (user:pass@host).
  const at = s.lastIndexOf("@");
  if (at >= 0) s = s.slice(at + 1);
  // Drop the port (IPv6 literals are handled below, before this point matters).
  if (!s.startsWith("[")) s = s.replace(/:\d+$/, "");
  s = s.replace(/\.+$/, ""); // trailing dot (FQDN form)

  if (!s) return { ok: false, error: "That does not contain a host name." };

  // IPv6 in brackets.
  if (s.startsWith("[") && s.endsWith("]")) {
    const inner = s.slice(1, -1);
    if (!/^[0-9a-f:]+$/.test(inner)) return { ok: false, error: "That does not look like a valid IP address." };
    return {
      ok: true,
      domain: inner,
      target: `http://[${inner}]`,
      warnings: ["IPv6 targets are scanned over plain HTTP by default."],
    };
  }

  const ip = IPV4_RE.exec(s);
  if (ip) {
    const octets = ip.slice(1).map(Number);
    if (octets.some((o) => o > 255)) return { ok: false, error: "Those octets do not form a valid IPv4 address." };
    // Plain HTTP is the honest default for a bare host: https to an arbitrary IP
    // usually fails the TLS handshake and the first recon round burns on that.
    return {
      ok: true,
      domain: s,
      target: `http://${s}`,
      warnings: ["Bare IPs are scanned over HTTP; HTTPS is tried automatically once a service is found."],
    };
  }

  if (LOCAL_SUFFIXES.some((sfx) => s.endsWith(sfx))) {
    return { ok: false, error: "That host is on a private suffix (.local/.internal/…). Use the public domain." };
  }
  if (!HOST_RE.test(s)) {
    return { ok: false, error: "That does not look like a domain name. Try something like example.com." };
  }

  const warnings: string[] = [];
  const labels = s.split(".");
  if (labels.length > 2) {
    warnings.push(
      `You entered the subdomain ${s}. The whole registered domain (${registrableDomain(s)}) is treated as in scope.`,
    );
  }
  return { ok: true, domain: s, target: `https://${s}`, warnings };
}

// registrableDomain is an approximation of eTLD+1 for the warning text only. The
// backend re-derives it properly with publicsuffix (db.RootDomain) when the scope
// row is written, so being wrong here is cosmetic, never authoritative.
const SECOND_LEVEL = new Set(["co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"]);
export function registrableDomain(host: string): string {
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const tld = labels[labels.length - 1];
  const sld = labels[labels.length - 2];
  const take = tld.length === 2 && SECOND_LEVEL.has(sld) ? 3 : 2;
  return labels.slice(-take).join(".");
}

// parseHostList splits the optional "additional in-scope hosts" textarea. Each entry
// is normalised and rejected individually so one typo cannot sink the whole form.
export function parseHostList(raw: string): { hosts: string[]; errors: string[] } {
  const hosts: string[] = [];
  const errors: string[] = [];
  for (const line of raw.split(/[\s,;]+/)) {
    if (!line.trim()) continue;
    const n = normalizeInput(line);
    if (!n.ok) {
      errors.push(`${line.trim()}: ${n.error}`);
      continue;
    }
    if (!hosts.includes(n.domain)) hosts.push(n.domain);
  }
  return { hosts, errors };
}

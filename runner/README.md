# ARTEX Kali Runner (Phase 1: network pack)

A separate, typed MCP service that performs network reconnaissance for ARTEX.
It exposes **fixed tools only** — there is no `run_command`, `run_tool`, shell
passthrough, or arbitrary argument injection. Every tool verifies a signed
per-task scope file before it builds an argv or resolves a target.

The runner is intentionally *not* part of the ARTEX process: it has no database
credentials, no ARTEX API token, and no shared filesystem beyond the two
operator-mounted directories (`scopes/` read-only, `artifacts/` read-write).

> For a task-oriented guide covering how it works and how to start it with or
> without Docker and ARTEX, see [`HOW-IT-WORKS.md`](HOW-IT-WORKS.md). This
> README remains the full configuration and scope-contract reference.

```
ARTEX ──writes──▶ data/scopes/<task_id>.json   (HMAC-signed)
   │                        │ read-only mount
   │                        ▼
   │                 kali-runner :8899/mcp  ──▶ nmap/dig/testssl.sh/…
   │                        │
   └──reads──────── data/tasks/<task_id>/runner/<job_id>/
                    manifest.json, result.json, stdout.txt, stderr.txt, raw tool output
```

## What is in the Phase 1 pack

| Tool | Purpose | Backing binary |
| --- | --- | --- |
| `net_nmap` | TCP/UDP discovery and service identification | `nmap` |
| `net_dns` | A/AAAA/MX/TXT/NS/SOA/CNAME/SRV/CAA, optional AXFR | `dig` |
| `net_tls` | TLS configuration and certificate review | `testssl.sh` |
| `net_snmp` | SNMP system enumeration (v1/v2c, single community) | `snmpwalk` |
| `net_smb` | Anonymous SMB shares/users/groups/sessions/policy | `enum4linux-ng` |
| `net_ldap` | Read-only anonymous LDAP/AD queries | `ldapsearch` |
| `net_ssh` | SSH banner and algorithm audit | `ssh-audit` |
| `job_wait` | Poll a job until it finishes or the wait budget expires | — |
| `job_cancel` | Cancel a job (process-group SIGTERM, then SIGKILL) | — |

Tool results are bounded. The full result is always written to
`result.json`; the model receives a compact envelope with at most 200
observation previews and a hard byte cap.

## Safety model

* **Default deny.** A missing, expired, tampered, or task-mismatched scope file
  is a structured `SCOPE_MISSING` / `SCOPE_EXPIRED` / `SCOPE_DENIED` error.
* **Signed scope.** ARTEX signs the canonical scope payload with
  `RUNNER_SCOPE_KEY` (HMAC-SHA256). The runner verifies before parsing.
* **Always blocked.** Loopback, link-local, multicast, unspecified, broadcast,
  and `169.254.169.254` are refused even if a scope tries to include them.
  The runner's own interface addresses and default gateways are also refused
  unless the *exact* address appears in the scope `ips` list.
* **No auto-widening.** Scope is never inferred from a target, a previous job,
  or a tool result. Ingestion never calls `AddAutoScope`.
* **Bounded resources.** Concurrency caps, per-task caps, wall-clock timeouts,
  output byte caps, artifact byte caps, and a request-body cap.
* **Process-group kill.** Tools run in their own session; cancellation and
  timeout kill the whole group, not just the parent.
* **No secrets in artifacts.** Command lines are redacted before they are
  written, and SNMP communities / credentials are never placed in
  `manifest.json` or `result.json`.
* **Read-only rootfs friendly.** The image runs as UID 10001 with a read-only
  root filesystem; only `/artifacts` and `/tmp` need to be writable.

## Quick start (Docker Compose)

The repository ships a `nonweb` compose profile that starts only the runner and
attaches it to a dedicated `control` network (ARTEX ⇄ runner) and an
`engagement` network (runner ⇄ targets). The runner is **not** on the default
ARTEX network and has no route to Postgres.

```bash
# 1. Generate secrets (32+ char token, 32-byte base64 scope key)
python -c "import secrets,base64; print(secrets.token_urlsafe(48)); print(base64.b64encode(secrets.token_bytes(32)).decode())"

# 2. Put them in .env. ARTEX_SCOPE_KEY must be the same value as
#    RUNNER_SCOPE_KEY: ARTEX signs, the runner verifies.
RUNNER_TOKEN=...
RUNNER_SCOPE_KEY=...
ARTEX_SCOPE_KEY=...

# 3. Start the runner
docker compose --profile nonweb up -d --build kali-runner

# 4. Health check (the port is exposed only on the control network)
docker compose --profile nonweb exec kali-runner curl -fsS http://127.0.0.1:8899/healthz
```

Register the MCP server in ARTEX:

| Field | Value |
| --- | --- |
| Name | `kali_runner` |
| Transport | `http` (Streamable HTTP) |
| URL | `http://kali-runner:8899/mcp` |
| Header | `Authorization: Bearer $RUNNER_TOKEN` |

ARTEX appends its untrusted-MCP note automatically; tool names appear as
`mcp__kali_runner__net_nmap`, etc.

## Configuration

All configuration is environment-only. Invalid or missing secrets abort
startup with exit code 2.

| Variable | Default | Notes |
| --- | --- | --- |
| `RUNNER_TOKEN` | — | **Required.** Bearer token, ≥ 32 characters. |
| `RUNNER_SCOPE_KEY` | — | **Required.** Base64 of exactly 32 random bytes. |
| `SCOPE_DIR` | `/scopes` | Read-only directory containing `<task_id>.json`. |
| `ARTIFACT_ROOT` | `/artifacts` | Writable root for `<task>/runner/<job>/`. |
| `RUNNER_HOST` | `0.0.0.0` | Bind address. |
| `RUNNER_PORT` | `8899` | Bind port. |
| `MAX_CONCURRENT_JOBS` | `4` | Global running-job cap (1–128). |
| `MAX_JOBS_PER_TASK` | `2` | Running-job cap per task (1–64). |
| `DEFAULT_TIMEOUT_S` | `600` | Tool timeout when the caller omits one. |
| `MAX_TIMEOUT_S` | `3600` | Hard timeout ceiling. |
| `MAX_OUTPUT_BYTES` | `1048576` | Sanitized stdout/stderr cap per stream. |
| `MAX_ARTIFACT_BYTES` | `67108864` | Total artifact bytes per job. |
| `JOB_RETENTION_S` | `86400` | How long finished jobs stay in memory. |
| `DNS_RESOLVERS` | empty | Comma-separated resolver list; empty uses the container resolver. |
| `TOOL_PACKS` | `net` | Only `net` is implemented in Phase 1. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |
| `HOME` | `/tmp` | Writable home for tools that insist on one. |
| `MAX_REQUEST_BYTES` | `1048576` | JSON-RPC body cap (1 KiB–16 MiB). |

## Scope file contract

`SCOPE_DIR/<task_id>.json`:

```json
{
  "schema": "artex.scope.v1",
  "task_id": 42,
  "company_id": 7,
  "engagement": "ACME Q4 external",
  "domains": ["example.com", "*.example.com", "api.example.com"],
  "ips": ["203.0.113.10", "2001:db8::10"],
  "cidrs": ["203.0.113.0/24", "2001:db8:1::/64"],
  "excludes": ["10.0.0.0/8", "admin.example.com"],
  "exclude_ports": [23, 3389],
  "policy": {
    "max_rate": 500,
    "max_hosts": 4096,
    "allow_syn": false,
    "allow_os_detect": false,
    "allow_axfr": false
  },
  "issued_at": "2026-11-09T10:00:00Z",
  "expires_at": "2026-11-10T10:00:00Z",
  "nonce": "b3f0c1d2e4a5968778695a4b3c2d1e0f",
  "signature": "hmac-sha256:…"
}
```

Canonicalization is fixed and must match between ARTEX and the runner:

1. Remove `signature`.
2. `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
3. UTF-8 encode, HMAC-SHA256 with `RUNNER_SCOPE_KEY`, lowercase hex.
4. Prefix with `hmac-sha256:`.

Target matching:

* `ips` — exact address only.
* `cidrs` — target must be fully inside one network; wildcard targets are
  rejected.
* `domains` — exact name, or `*.example.com` which matches subdomains but not
  the apex.
* `excludes` always win over includes.
* `exclude_ports` are removed from every scan and cannot be requested.

Optional operator exclusions live beside the signed file in
`SCOPE_DIR/<task_id>.exclude.json`. The ARTEX exporter merges them into the
signed scope; the runner never reads this file directly.

## Jobs and artifacts

Tools with `wait_s > 0` run synchronously up to that budget and return the
final envelope. With `wait_s = 0` they return a `running` envelope and the
agent must poll with `job_wait`. A tool that exceeds `wait_s` but not its
`timeout_s` keeps running; the caller gets `state: "running"` and polls.

Artifacts are written under:

```
<ARTIFACT_ROOT>/<task_id>/runner/<job_id>/
  manifest.json    # schema, tool, argv_redacted, versions, files + SHA-256
  result.json      # full observations, warnings, error, state
  stdout.txt       # sanitized, capped
  stderr.txt       # sanitized, capped
  <tool>.xml|json|txt|ldif …
```

Every write is `tmp + fsync + rename`, mode `0640`. `manifest.json` is
written last and contains a SHA-256 for each file. ARTEX maps this directory to
`data/tasks/<task_id>/runner/<job_id>/` so the evidence is visible in the file
manager and can be cited from findings.

The model-facing envelope always includes `result_artifact` early:

```json
{
  "schema": "artex.runner.v1",
  "ok": true,
  "job_id": "01J…",
  "task_id": 42,
  "tool": "net_nmap",
  "state": "succeeded",
  "result_artifact": {"name": "result.json", "path": "42/runner/01J…/result.json", "bytes": 12345, "sha256": "…"},
  "artifacts": [ … ],
  "observations_total": 57,
  "observations_truncated": false,
  "observations": [ … ],
  "truncated": false,
  "warnings": [],
  "error": null
}
```

ARTEX caps tool output at 30k characters; the ingestion hook reads
`result_artifact` from the envelope, loads the full `result.json` from the
shared artifact mount, and persists only `ip` and `service` observations
(`service_type = "other"`). It never widens `task_scope`.

## Operator runbook

1. **Generate and store secrets.** `RUNNER_TOKEN`, `RUNNER_SCOPE_KEY`, and
   `ARTEX_SCOPE_KEY` live only in `.env` (or your secret manager). The two scope
   keys must be identical. Rotating either key requires restarting both
   containers; rotating the token also requires updating the MCP server header
   in ARTEX.
2. **Start the runner.**
   `docker compose --profile nonweb up -d --build kali-runner`
3. **Confirm health.**
   `docker compose --profile nonweb exec kali-runner curl -fsS http://127.0.0.1:8899/healthz`
   → `{"status":"ok"}`.
4. **Register MCP.** Name `kali_runner`, transport `http`, URL
   `http://kali-runner:8899/mcp`, bearer header as above.
5. **Bind the skill.** `network-recon` is seeded visible to `auto`, `pentest`,
   and `worker` agents. Load it in the task before asking for scans.
6. **Create a task and scope.** Add at least one `ip`, `cidr`, or
   `root_domain`. Confirm `data/scopes/<task_id>.json` exists and is signed.
7. **Run a smoke scan.** Ask for a top-1000 TCP scan of an in-scope host.
8. **Verify evidence.** Check `assets` for the IP/service rows and
   `data/tasks/<task_id>/runner/<job_id>/manifest.json`.
9. **Negative test.** Ask for an out-of-scope target (for example
   `8.8.8.8`); the runner returns `SCOPE_DENIED` and the agent must not retry.
10. **Teardown.** Stop the container, archive `data/tasks/<task>/runner/`,
    rotate the token, and remove the container. In-flight jobs are cancelled on
    shutdown; finished artifacts remain readable.

### Intercept rules

The following are seeded as `ask` (human approval) because they are noisy,
intrusive, or likely to trigger IDS:

* full TCP scan (`profile = "full_tcp"`)
* SYN scan (`syn = true`)
* OS detection (`os_detect = true`)
* DNS zone transfer (`axfr = true`)

Everything else runs without an additional prompt, subject to scope. Phase 2
adds AD/credential rules; do not add them to the Phase 1 seed.

### Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `SCOPE_MISSING` | No signed file yet, or `SCOPE_DIR`/task ID mismatch. |
| `SCOPE_EXPIRED` | `expires_at` passed; re-export from ARTEX. |
| `SCOPE_DENIED` for a valid target | Target not covered, excluded, or blocked (loopback/metadata/runner address). |
| `TOOL_FAILED` with no stdout | Binary missing from the image or target filtered; check `stderr.txt`. |
| `JOB_LIMIT` | Global or per-task concurrency cap reached; wait or cancel. |
| `401` | Missing/incorrect bearer token, or token rotated without updating ARTEX. |
| Artifacts absent | `ARTIFACT_ROOT` not mounted writable or volume permissions wrong. |

## Lab setup

A minimal acceptance lab (all on the `engagement` network, never on the
control network):

| Host | Services |
| --- | --- |
| `lab-linux` | `sshd`, `nginx` with a deliberately weak TLS protocol/cipher |
| `lab-smb` | Samba with anonymous share enumeration |
| `lab-ldap` | OpenLDAP with a small seeded directory |
| `lab-snmp` | `snmpd` with a known test community |

Then:

1. Create an ARTEX task and add the lab CIDR (for example `172.28.0.0/24`) to
   scope.
2. Run `net_nmap` with `profile=top1000` against `lab-linux`.
3. Run `net_smb mode=all`, `net_ldap`, `net_snmp`, `net_tls`, `net_ssh`
   against their hosts.
4. Verify each acceptance criterion in
   `docs/non-web-capability-runner.md` §11.4, including the negative scope
   test, the approval gates, artifact hashes, and transcript size.
5. Run the security checks in §11.5 (`docker inspect` for privileges, XXE
   fixture, oversized body, path traversal, secret scan of artifacts).

## Development

```bash
cd runner
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest -q
```

`requirements.lock` is the production lock (Python 3.12). Regenerate it only
from a clean Linux/Python 3.12 environment and rebuild the image afterward.

Run locally without Docker:

```bash
export RUNNER_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
export RUNNER_SCOPE_KEY="$(python -c 'import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())')"
export SCOPE_DIR=./scopes ARTIFACT_ROOT=./artifacts
python -m runner
```

## Known limitations (Phase 1)

* Compose is not a firewall. For client work, run the runner in a dedicated
  VM/network namespace with an egress allowlist.
* Jobs are in-memory; a runner restart loses in-flight work (artifacts and
  `result.json` are durable).
* Only `ip` and `service` observations are ingested. DNS/SMB/LDAP/SNMP/TLS
  findings are returned to the model and stored in artifacts, but are not
  first-class graph entities until Phase 2.
* Credentials are not yet modeled; SMB/LDAP support `credential_id` in the
  schema but Phase 1 runs anonymously.
* Artifacts live under the task data directory and are visible to the file
  manager. Phase 2 must move sensitive captures to a restricted path.
* One runner should serve one client. Never give a single runner a union of
  unrelated scopes.

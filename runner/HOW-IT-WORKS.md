# Kali Runner — How It Works and How to Run It

Status: Phase 1 (network pack)

The `kali-runner` is an optional, separate MCP service that gives ARTEX typed
network-reconnaissance tools. It is deliberately **not** a shell bridge: there
is no `run_command`, `run_tool`, or arbitrary-argument endpoint. Every scan
call is checked against an HMAC-signed, per-task scope file before a process is
started.

This document explains the moving parts and the ways to start it:

- with ARTEX and Docker (recommended)
- with ARTEX, runner without Docker (mixed mode)
- without ARTEX (runner only, for testing)
- without the runner (the default ARTEX stack)

**Short version:** put `RUNNER_TOKEN`, `RUNNER_SCOPE_KEY`, and the same value in
`ARTEX_SCOPE_KEY` in `.env`, run
`docker compose --profile nonweb up -d --build`, then register the MCP server
`kali_runner` at `http://kali-runner:8899/mcp` with the bearer header. The rest
of this document explains why and covers the other modes.

The authoritative implementation spec is
[`docs/non-web-capability-runner.md`](../docs/non-web-capability-runner.md).
The full configuration reference and scope contract are in
[`runner/README.md`](README.md).

---

## 1. What it is

ARTEX already orchestrates agents, tools, approvals, assets, and reporting.
The runner adds the non-web execution layer:

| Piece | Responsibility |
| --- | --- |
| ARTEX | Task scope, signed scope export, skill gating, approvals, observation ingestion, assets, findings, reporting |
| `kali-runner` | Bearer auth, scope verification, typed tool contracts, job execution, parsing, artifacts, audit log |
| Target network | Hosts, services, DNS, TLS, SMB, LDAP, SNMP, SSH |

The runner has no database credentials, no ARTEX API token, and no shared
filesystem with ARTEX beyond two operator-mounted directories:

- `scopes/` — read-only signed authorization files
- `artifacts/` — writable task evidence

```
┌────────────────────────── ARTEX container ──────────────────────────┐
│                                                                     │
│  task_scope ──► scope exporter ──► data/scopes/<task_id>.json       │
│                                          (HMAC-signed)              │
│                                                                     │
│  agent ──► network-recon skill ──► MCP client ──┐                   │
│                                                 │                   │
│  observation hook ◄── result.json ◄─────────────┼── artifacts       │
│         │                                       │                   │
│         ▼                                       │                   │
│  assets: ip / service                           │                   │
└─────────────────────────────────────────────────┼───────────────────┘
                                                  │ control network
                              ┌───────────────────▼───────────────────┐
                              │ kali-runner :8899/mcp                 │
                              │ auth → scope → job → tool → parse     │
                              │ artifact writer + manifest + audit    │
                              └───────────────────┬───────────────────┘
                                                  │ engagement network
                                          targets / VPN / lab
```

---

## 2. How it works

### 2.1 ARTEX side

1. **Scope is stored in `task_scope`.** A task can have `ip`, `cidr`,
   `root_domain`, `subdomain`, or company-scope entries. For network
   authorization, `icp` and `keyword` entries are ignored.
2. **The scope exporter writes a signed file.** On startup, on task-scope
   changes, and on task launch/restore, ARTEX writes
   `data/scopes/<task_id>.json` (inside the container:
   `/app/data/scopes/<task_id>.json`). A 30-second reconciler rewrites files
   whose authorization changed or whose expiry is close. The file is written
   atomically with mode `0640`.
3. **The skill unlocks the tools.** The shipped `network-recon` skill declares
   `mcps: kali_runner`. ARTEX defers the runner's MCP tools until that skill is
   loaded, so web-only agents do not see network tools by default.
4. **Approvals gate noisy actions.** Built-in intercept rules ask for approval
   before `full_tcp`, `syn`, `os_detect`, and `axfr`. `net_snmp` is explicitly
   allowed because a single-community read-only walk is low-impact.
5. **Results are ingested.** When a runner tool returns, ARTEX's observation
   hook reads the envelope, loads the full `result.json` from the artifact
   mount, validates its path and SHA-256, and upserts `ip` and `service`
   observations into `assets` (`service_type = "other"`). It never widens
   `task_scope` and never calls `AddAutoScope`.

### 2.2 Runner side

1. **Bearer auth.** `POST /mcp` requires `Authorization: Bearer <RUNNER_TOKEN>`.
   `/healthz` is unauthenticated and returns `{"status":"ok"}`.
2. **Scope verification.** The runner loads
   `<SCOPE_DIR>/<task_id>.json`, verifies the HMAC, checks the task ID, expiry,
   and issue time, then builds a normalized scope. A missing, expired, tampered,
   or task-mismatched file is a structured error, not a crash.
3. **Target authorization.** Every target is matched against the signed scope
   before a process starts. CIDRs must be fully contained; wildcard domains
   match subdomains but not the apex; excludes always win.
4. **Job execution.** Tools run as subprocesses in their own process group with
   a bounded timeout, output caps, and concurrency caps. Long jobs return a
   `running` envelope and are polled with `job_wait`.
5. **Parsing and artifacts.** Raw output is written under
   `<ARTIFACT_ROOT>/<task_id>/runner/<job_id>/`; the parser turns it into
   observations; `result.json` and `manifest.json` are written last. Every write
   is `tmp + fsync + rename`.
6. **Audit.** Startup, authorization denials, and tool failures are written as
   one-line JSON to stdout. Command lines are redacted before they are logged
   or written to artifacts.

### 2.3 A request, end to end

1. The agent loads `network-recon`, which unlocks `mcp__kali_runner__*` tools.
2. The agent calls `net_nmap` with `task_id`, `target`, and a fixed profile.
3. ARTEX checks intercept rules. A `full_tcp`/SYN/OS/AXFR request waits for
   human approval; a normal `top100` scan proceeds.
4. The runner authenticates the request, verifies the signed scope, authorizes
   the target, and queues a job.
5. The tool runs. With `wait_s > 0` the call waits up to that budget; with
   `wait_s = 0` it returns immediately with a job ID.
6. The runner parses stdout/XML/JSON/LDIF, writes artifacts, and returns a
   compact envelope. The envelope always carries `result_artifact` early so it
   survives ARTEX's 30k-character tool-output cap.
7. If the job is still running, the agent polls `job_wait`; it can stop work
   with `job_cancel`.
8. ARTEX reads the full `result.json`, ingests `ip`/`service` observations, and
   the model sees only the bounded summary.
9. The agent can cite `manifest.json` and `result.json` when recording findings.

### 2.4 Scope: the hard boundary

`data/scopes/<task_id>.json` looks like this:

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

Signing is fixed and must match on both sides:

1. Remove `signature`.
2. `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
3. UTF-8 encode and HMAC-SHA256 with `RUNNER_SCOPE_KEY`.
4. Prefix the lowercase hex digest with `hmac-sha256:`.

Target matching:

- `ips` — exact address only.
- `cidrs` — the target must be fully inside one network. A `/16` target will
  fail `max_hosts` (default 4096) and must be split.
- `domains` — exact name, or `*.example.com`, which matches subdomains but not
  `example.com` itself.
- `excludes` — always win over includes.
- `exclude_ports` — removed from every scan and cannot be requested.

Always blocked, even if a scope tries to include them:

- loopback (`127.0.0.0/8`, `::1`)
- link-local (`169.254.0.0/16`, `fe80::/10`)
- multicast and unspecified
- `255.255.255.255`
- the cloud metadata address `169.254.169.254`
- the runner's own interface addresses and default gateways, unless the
  **exact** address appears in the scope `ips` list

RFC1918 addresses are allowed only when they are covered by the task scope.

**Operator exclusions.** An operator can add
`data/scopes/<task_id>.exclude.json` next to the signed file:

```json
{
  "domains": ["admin.example.com"],
  "ips": ["203.0.113.5"],
  "cidrs": ["10.0.0.0/8"],
  "ports": [23, 3389]
}
```

ARTEX merges this into the signed scope; the runner never reads the exclusion
file directly. Changes are picked up by the 30-second reconciler.

**Scope lifetime.** `ARTEX_SCOPE_TTL` defaults to `720h` (30 days). The exporter
preserves an existing signed file when the authorization content is unchanged
and more than 24 hours remain, so the directory is not rewritten every 30
seconds.

### 2.5 Jobs

Every network tool accepts `wait_s` (`0`–`120`, default `30`):

- `wait_s > 0` — the call waits up to that budget. If the tool finishes, the
  final envelope is returned. If not, the envelope says `state: "running"` and
  includes the job ID.
- `wait_s = 0` — return immediately with a job ID.

`job_wait` takes `job_id` and an optional `timeout_s` (`1`–`60`, default `30`).
`job_cancel` takes `job_id` and returns the final state. Neither requires
`task_id`; the endpoint is token-protected and job IDs are ULIDs.

Limits:

- global running jobs: `MAX_CONCURRENT_JOBS` (default `4`)
- running jobs per task: `MAX_JOBS_PER_TASK` (default `2`)
- tool timeout: `DEFAULT_TIMEOUT_S` (default `600`), ceiling
  `MAX_TIMEOUT_S` (default `3600`)
- finished jobs stay in memory for `JOB_RETENTION_S` (default `86400`)

Cancellation and timeout kill the whole process group (POSIX `SIGTERM`, then
`SIGKILL`). Jobs are in memory; a runner restart loses in-flight work, but
completed artifacts remain on disk.

### 2.6 Artifacts and observations

Artifacts are written under:

```
<ARTIFACT_ROOT>/<task_id>/runner/<job_id>/
  manifest.json    # schema, tool, argv_redacted, versions, files + SHA-256
  result.json      # full observations, warnings, error, state
  stdout.txt       # sanitized and byte-capped
  stderr.txt       # sanitized and byte-capped
  <tool>.xml|json|txt|ldif …
```

With the Compose setup, `ARTIFACT_ROOT` is `/artifacts`, mounted from
`./data/tasks`, so the host path is:

```
data/tasks/<task_id>/runner/<job_id>/
```

The model-facing envelope is bounded (at most 200 observation previews plus a
byte cap), but `result.json` is complete. ARTEX's ingestion hook reads the
`result_artifact` reference, validates the path is inside the task directory,
checks size and SHA-256, and persists only `ip` and `service` observations.
DNS, TLS, SMB, LDAP, SNMP, and SSH details remain in `result.json` and the raw
tool files for Phase 1.

### 2.7 Tool surface

| Tool | Purpose | Main inputs |
| --- | --- | --- |
| `net_nmap` | TCP/UDP discovery and service identification | `task_id`, `target`, `profile` (`discovery`, `top100`, `top1000`, `full_tcp`, `udp_top100`, `custom`), optional `ports`, `rate`, `scripts`, `syn`, `os_detect`, `timeout_s`, `wait_s` |
| `net_dns` | DNS records, resolution, optional AXFR | `task_id`, `target`, optional `record_types`, `resolver`, `axfr` |
| `net_tls` | TLS configuration and certificate review | `task_id`, `target` (host or `host:port`), `profile` (`quick`, `full`), `starttls` |
| `net_snmp` | SNMP system enumeration (v1/v2c, single community) | `task_id`, `target`, `version`, `community` |
| `net_smb` | Anonymous SMB shares/users/groups/sessions/policy | `task_id`, `target`, `mode` (`shares`, `users`, `groups`, `sessions`, `policy`, `all`) |
| `net_ldap` | Read-only anonymous LDAP/AD queries | `task_id`, `target`, optional `port`, `base_dn`, `filter`, `attributes`, `scope`, `use_tls`, `max_entries` |
| `net_ssh` | SSH banner and algorithm audit | `task_id`, `target`, optional `port` |
| `job_wait` | Poll a running job | `job_id`, optional `timeout_s` |
| `job_cancel` | Cancel a job | `job_id` |

Phase 1 notes:

- SNMPv3 is accepted by the schema but returns `NOT_IMPLEMENTED`.
- `credential_id` is reserved for Phase 2; SMB/LDAP run anonymously.
- There is no exploitation, credential dumping, lateral movement, or persistence.

### 2.8 Skill and approvals

`skills/network-recon/SKILL.md` declares:

```yaml
mcps: kali_runner
```

ARTEX exposes the tools as `mcp__kali_runner__<tool>`. The server name must be
exactly `kali_runner`; the skill binding and the seeded intercept rules both
depend on it.

The skill is seeded visible to `auto`, `pentest`, and `worker` agents. Existing
installations pick it up on startup with insert-if-absent semantics; a user's
later toggle-off is not overwritten. If the skill is not visible for an agent,
enable it in the agent's skill visibility UI.

---

## 3. Choose a start mode

| Mode | ARTEX | Runner | Use case |
| --- | --- | --- | --- |
| A | Docker | Docker, `nonweb` profile | Recommended for labs and engagements |
| B | Docker | none | Default ARTEX; web-only workflow |
| C | none | Docker, runner only | Standalone tool testing |
| D | Docker | local Python | Debugging tools/parsers with ARTEX-exported scope |
| E | none | local Python | Runner development and unit tests |

The `nonweb` profile is opt-in. Plain `docker compose up` does **not** start the
runner and does not require any runner secrets.

---

## 4. Prerequisites and secrets

### 4.1 Generate secrets once

Generate them once and store them in `.env` (or your secret manager). Do not
regenerate them on every start: a new scope key requires ARTEX to re-sign every
scope file, and a new token breaks the MCP registration in ARTEX.

Linux/macOS:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

PowerShell:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

- `RUNNER_TOKEN` — at least 32 characters; used as the bearer token.
- `RUNNER_SCOPE_KEY` — base64 of exactly 32 random bytes; used by the runner to
  verify scope files.
- `ARTEX_SCOPE_KEY` — **the same value** as `RUNNER_SCOPE_KEY`; used by ARTEX to
  sign scope files.

### 4.2 `.env`

Add or update these entries in the repository root `.env`:

```dotenv
RUNNER_TOKEN=<generated token>
RUNNER_SCOPE_KEY=<generated 32-byte base64 key>
ARTEX_SCOPE_KEY=<same value as RUNNER_SCOPE_KEY>
ARTEX_SCOPE_DIR=/app/data/scopes
```

`ARTEX_SCOPE_DIR` is the path **inside the ARTEX container**. The host
`./data/scopes` directory is mounted read-only into the runner at `/scopes`.
Unset `ARTEX_SCOPE_KEY` to disable scope export; the default ARTEX stack then
behaves exactly as before.

Optional ARTEX-side policy:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ARTEX_SCOPE_TTL` | `720h` | Signed-scope lifetime |
| `ARTEX_SCOPE_POLICY_MAX_RATE` | `500` | Max `nmap` rate (1–1000) |
| `ARTEX_SCOPE_POLICY_MAX_HOSTS` | `4096` | Max hosts per CIDR target (1–65536) |
| `ARTEX_SCOPE_ALLOW_SYN` | `false` | Allow `syn=true` |
| `ARTEX_SCOPE_ALLOW_OS_DETECT` | `false` | Allow `os_detect=true` |
| `ARTEX_SCOPE_ALLOW_AXFR` | `false` | Allow DNS zone transfer |

Enabling SYN or OS detection also requires `cap_add: [NET_RAW]` in the Compose
service and an approval through the intercept rule. Scope policy is the hard
gate; the approval is the human gate.

---

## 5. Mode A — ARTEX and runner with Docker (recommended)

### 5.1 Start

From the repository root:

```bash
docker compose --profile nonweb up -d --build
```

This starts PostgreSQL, ARTEX, and the runner. The `control` network is
internal (ARTEX ⇄ runner); the runner reaches targets through the separate
`engagement` network. For a lab/LAN-only engagement, set `engagement` to
`internal: true`; for external targets, use a dedicated egress VM or network
namespace with an allowlist. If ARTEX is already running:

```bash
docker compose up -d --build
docker compose --profile nonweb up -d --build kali-runner
```

Check status and logs:

```bash
docker compose --profile nonweb ps
docker compose --profile nonweb logs -f kali-runner
docker compose logs artex --tail=100
```

Health check (the runner port is not published to the host):

```bash
docker compose --profile nonweb exec kali-runner \
  curl -fsS http://127.0.0.1:8899/healthz
```

Expected:

```json
{"status":"ok"}
```

### 5.2 Register the MCP server in ARTEX

Open the MCP servers page in ARTEX (System → MCP) and add:

| Field | Value |
| --- | --- |
| Name | `kali_runner` |
| Transport | `http` |
| URL | `http://kali-runner:8899/mcp` |
| Headers | `Authorization=Bearer <RUNNER_TOKEN>` |
| Enabled | yes |
| Timeout | `120` seconds |

In the UI, the headers field is one `KEY=VALUE` per line. In the API, it is the
`env` map:

```json
{"Authorization": "Bearer <RUNNER_TOKEN>"}
```

The header is stored in ARTEX's database, so treat the database as trusted and
rotate the token per engagement. The exact name `kali_runner` matters: the
`network-recon` skill and the seeded intercept rules refer to it.

### 5.3 Create a task and scope

In ARTEX:

1. Create or open a task.
2. Add at least one network scope entry:
   - `ip` — a single host, for example `192.168.56.10`
   - `cidr` — a range, for example `192.168.56.0/24`
   - `root_domain` — emits the apex and `*.example.com`
   - `subdomain` — emits the exact host
   - company scope — `domain`, `ip`, and `cidr` entries are included
3. Wait up to 30 seconds, or trigger a scope change, then verify:

```bash
python -m json.tool data/scopes/<task_id>.json
```

If the file is missing:

- confirm `ARTEX_SCOPE_KEY` is set in the ARTEX container;
- check `docker compose logs artex --tail=100` for `[scope]` messages;
- confirm `ARTEX_SCOPE_DIR` matches the mounted path (`/app/data/scopes` by
  default).

An empty scope file is valid but authorizes nothing.

### 5.4 Load the skill and run a smoke test

In the task, load `network-recon` (it should already be visible to `auto`,
`pentest`, and `worker`). Then ask for a small scan:

```text
Use the network-recon skill. Run net_nmap with task_id=<id>,
target=192.168.56.10, profile=top100, wait_s=30.
```

`top100` and `top1000` do not need approval. `full_tcp`, `syn`, `os_detect`, and
`axfr` will wait for human approval.

For a direct MCP call from the host, publish the port as shown in
[§6.3](#63-optional-publish-the-port-for-a-host-client) first.

### 5.5 Verify evidence

Check the artifact directory on the host:

```
data/tasks/<task_id>/runner/<job_id>/
  manifest.json
  result.json
  stdout.txt
  stderr.txt
```

`manifest.json` contains the redacted argv, tool versions, file list, and
SHA-256 for each file. `result.json` contains the full observations.

Check that ARTEX ingested the network facts:

- `assets` has an `ip` row for the target;
- `assets` has `service` rows with `service_type = "other"` for discovered
  ports.

Then run a negative test: ask for an address that is not in scope, for example
`8.8.8.8`. The runner should return `SCOPE_DENIED`, and the agent must not retry
with a different spelling or a neighbouring address.

### 5.6 Stop and disable

Stop only the runner:

```bash
docker compose --profile nonweb stop kali-runner
docker compose --profile nonweb rm -f kali-runner
```

Stop the whole Compose project, including the runner profile:

```bash
docker compose --profile nonweb down
```

`down` removes containers and networks; named volumes such as `pgdata` remain.
Finished artifacts under `data/tasks/` remain on the host.

To disable scope export without removing the runner:

1. Remove or unset `ARTEX_SCOPE_KEY` in `.env`.
2. Restart ARTEX: `docker compose up -d --force-recreate artex`.
3. Optionally delete `data/scopes/*.json` when decommissioning the engagement.

Existing signed files are not deleted automatically. The runner will keep
accepting them until they expire, so delete them if you are ending the
engagement.

---

## 6. Mode C — runner only, without ARTEX

This is useful for testing the runner and its parsers. There is no automatic
scope export, no skill gating, and no observation ingestion. You must provide a
signed scope file yourself.

### 6.1 Start the runner container

From the repository root:

```bash
mkdir -p data/scopes data/tasks
docker compose --profile nonweb up -d --build kali-runner
```

The runner refuses to start if `RUNNER_TOKEN` or `RUNNER_SCOPE_KEY` is empty or
invalid. Put them in `.env` first, or pass them explicitly.

### 6.2 Create a signed scope file

Save this as `make_scope.py` and run it with the same scope key the runner uses:

```python
#!/usr/bin/env python3
"""Create a local/lab signed scope file for the kali-runner.

This is for standalone testing only. In normal operation ARTEX writes this file.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

task_id = int(os.environ.get("TASK_ID", "1"))
scope_dir = Path(os.environ.get("SCOPE_DIR", "data/scopes"))
key = base64.b64decode(os.environ["RUNNER_SCOPE_KEY"])

now = datetime.now(timezone.utc).replace(microsecond=0)
payload = {
    "schema": "artex.scope.v1",
    "task_id": task_id,
    "company_id": None,
    "engagement": "local-lab",
    "domains": [],
    # Replace with your lab target. Loopback/link-local/metadata are always blocked.
    "ips": ["192.168.56.10"],
    "cidrs": ["192.168.56.0/24"],
    "excludes": [],
    "exclude_ports": [],
    "policy": {
        "max_rate": 500,
        "max_hosts": 4096,
        "allow_syn": False,
        "allow_os_detect": False,
        "allow_axfr": False,
    },
    "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "expires_at": (now + timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "nonce": secrets.token_hex(16),
}

canonical = json.dumps(
    payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
payload["signature"] = "hmac-sha256:" + hmac.new(
    key, canonical, hashlib.sha256
).hexdigest()

scope_dir.mkdir(parents=True, exist_ok=True)
path = scope_dir / f"{task_id}.json"
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(path)
```

Run it:

```bash
export RUNNER_SCOPE_KEY='<same base64 key as the runner>'
export SCOPE_DIR=./data/scopes
export TASK_ID=1
python make_scope.py
```

The file `data/scopes/1.json` is mounted into the runner at `/scopes/1.json`.
The runner caches scope files for 5 seconds, so allow a moment after rewriting.

### 6.3 Optional: publish the port for a host client

The Compose service uses `expose`, not `ports`, so it is not published to the
host; ARTEX reaches it over the `control` network. For local testing, create
`docker-compose.override.yml`:

```yaml
services:
  kali-runner:
    ports:
      - "127.0.0.1:8899:8899"
```

Then:

```bash
docker compose --profile nonweb up -d --build kali-runner
```

Do not publish this port on `0.0.0.0` for a real engagement. ARTEX reaches the
runner over the `control` network and does not need a host port.

A minimal FastMCP client:

```python
import asyncio
import os

from fastmcp import Client
from fastmcp.client.auth import BearerAuth


async def main():
    async with Client(
        "http://127.0.0.1:8899/mcp",
        auth=BearerAuth(os.environ["RUNNER_TOKEN"]),
    ) as client:
        tools = await client.list_tools()
        print([tool.name for tool in tools])

        result = await client.call_tool(
            "net_nmap",
            {
                "task_id": 1,
                "target": "192.168.56.10",
                "profile": "top100",
                "wait_s": 30,
            },
        )
        print(result)


asyncio.run(main())
```

Install the client if needed:

```bash
python -m pip install "fastmcp>=4,<5"
```

If the call returns `state: "running"`, poll:

```python
await client.call_tool("job_wait", {"job_id": "<job-id>", "timeout_s": 30})
```

### 6.4 What is missing without ARTEX

- No signed scope is generated automatically.
- No `network-recon` skill gating or approvals.
- No `ip`/`service` ingestion into `assets`.
- No task/artifact association beyond the `task_id` you put in the scope file.

The artifacts themselves are still written under
`data/tasks/<task_id>/runner/<job_id>/`.

---

## 7. Mode D/E — run the Python service without Docker

### 7.1 Install

Use Linux, Kali, or WSL2 for the full network pack. The runner itself runs on
Windows, but several tools and process-group semantics are POSIX-oriented.

```bash
cd runner
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

The Python package only wraps the external binaries. Install the ones you plan
to use and make sure they are on `PATH`:

| Tool | Binary |
| --- | --- |
| `net_nmap` | `nmap` |
| `net_dns` | `dig` |
| `net_tls` | `testssl.sh` |
| `net_snmp` | `snmpwalk` |
| `net_smb` | `enum4linux-ng` |
| `net_ldap` | `ldapsearch` |
| `net_ssh` | `ssh-audit` |

The exact package list used by the production image is in
[`runner/Dockerfile`](Dockerfile). A missing binary produces a structured
`TOOL_FAILED`, not a crash.

### 7.2 Configure

Generate secrets once (see [§4.1](#41-generate-secrets-once)) and export the
same values on every start.

Linux/macOS:

```bash
export RUNNER_TOKEN='<token>'
export RUNNER_SCOPE_KEY='<32-byte base64 key>'
export SCOPE_DIR=./scopes
export ARTIFACT_ROOT=./artifacts
export RUNNER_HOST=127.0.0.1
python -m runner
```

PowerShell:

```powershell
$env:RUNNER_TOKEN = "<token>"
$env:RUNNER_SCOPE_KEY = "<32-byte base64 key>"
$env:SCOPE_DIR = ".\scopes"
$env:ARTIFACT_ROOT = ".\artifacts"
$env:RUNNER_HOST = "127.0.0.1"
python -m runner
```

The service listens on `http://127.0.0.1:8899` with `RUNNER_HOST=127.0.0.1`.
The default is `0.0.0.0`; only use that when a container or another host must
reach it, and firewall the port.

### 7.3 Scope

For Mode E (no ARTEX), save the script from
[§6.2](#62-create-a-signed-scope-file) in the current directory, then create a
signed scope file:

```bash
export SCOPE_DIR=./scopes
export TASK_ID=1
python make_scope.py
```

For Mode D (ARTEX in Docker, runner on the host), let ARTEX write the scope
files and point the local runner at the same host directory. These paths are
relative to the `runner/` directory; from the repository root they are
`./data/scopes` and `./data/tasks`.

```bash
export SCOPE_DIR=../data/scopes
export ARTIFACT_ROOT=../data/tasks
```

Then register the MCP server in ARTEX with a URL that reaches the host:

- Docker Desktop: `http://host.docker.internal:8899/mcp`
- Linux: use the host bridge address, or add
  `extra_hosts: ["host.docker.internal:host-gateway"]` to the `artex` service
  and use `http://host.docker.internal:8899/mcp`
- Bind the runner to an address reachable from the container, not only
  `127.0.0.1` (for example `RUNNER_HOST=0.0.0.0`), and allow the port through
  the host firewall.

Both processes must be able to read/write the shared `data/scopes` and
`data/tasks` directories. On Linux, match UID/GID or make the directories
group-writable if the container user differs from your login.

### 7.4 Run tests

From `runner/`:

```bash
python -m pytest -q
```

Some process-group tests are POSIX-only and skip on Windows. `requirements.lock`
is the production lock for the Python 3.12 image; regenerate it only from a
clean Linux/Python 3.12 environment.

---

## 8. Mode B — ARTEX without the runner

This is the default and requires no changes:

```bash
docker compose up -d --build
```

- The `kali-runner` service has `profiles: ["nonweb"]`, so it is not started.
- `ARTEX_SCOPE_KEY` can remain unset; scope export is then disabled and ARTEX
  logs `ARTEX_SCOPE_KEY not set — non-web runner scope export disabled`.
- The web workflow, existing MCP servers, and existing skills are unchanged.

If you previously enabled the runner and want to return to this mode:

1. `docker compose --profile nonweb stop kali-runner`
2. Remove `ARTEX_SCOPE_KEY` from `.env`.
3. Restart ARTEX: `docker compose up -d --force-recreate artex`.
4. Optionally delete `data/scopes/*.json` and disable `network-recon` per agent
   in the skill visibility UI.

The `network-recon` skill may remain visible, but without a registered
`kali_runner` MCP server its tools are not available.

---

## 9. Rotation and teardown

### Rotate the bearer token

1. Generate a new `RUNNER_TOKEN`.
2. Update `.env`.
3. Recreate the runner:
   `docker compose --profile nonweb up -d --force-recreate kali-runner`
4. Update the `Authorization` header on the `kali_runner` MCP server in ARTEX.

### Rotate the scope key

1. Generate a new 32-byte base64 key.
2. Set **both** `RUNNER_SCOPE_KEY` and `ARTEX_SCOPE_KEY` to the new value.
3. Recreate ARTEX and the runner:

   ```bash
   docker compose --profile nonweb up -d --force-recreate artex kali-runner
   ```

4. ARTEX re-signs scope files on the next sync (startup or the 30-second
   reconciler). Confirm `data/scopes/<task_id>.json` has a new `signature`.

If only one side is updated, calls fail with `SCOPE_DENIED` (signature
verification failure), or `SCOPE_MISSING` until a new file is written.

### End an engagement

1. Stop the runner:
   `docker compose --profile nonweb stop kali-runner`
2. Archive `data/tasks/<task_id>/runner/` to evidence storage.
3. Delete the runner container and, if desired, the scope files:
   `docker compose --profile nonweb rm -f kali-runner`
   `rm data/scopes/<task_id>.json`
4. Rotate the token and scope key; do not reuse a runner across clients.

---

## 10. Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Runner exits with `configuration error: RUNNER_TOKEN is required` | Set `RUNNER_TOKEN` to at least 32 characters. |
| `RUNNER_SCOPE_KEY must decode to exactly 32 bytes` | Generate the key with `base64.b64encode(secrets.token_bytes(32))`. |
| Container exits immediately | `docker compose --profile nonweb logs kali-runner`; check secrets and mounts. |
| `401 Unauthorized` | Bearer token missing or different from `RUNNER_TOKEN`; re-check the MCP header after rotation. |
| `SCOPE_MISSING` | No signed file, `SCOPE_DIR` wrong, task ID mismatch, or `ARTEX_SCOPE_KEY` unset in ARTEX. Wait 30 seconds and check `data/scopes/`. |
| `SCOPE_EXPIRED` | `expires_at` passed; re-export/re-sync from ARTEX. |
| `SCOPE_DENIED` for a valid target | Target is not covered, is excluded, is always-blocked (loopback/link-local/metadata/runner address), or violates `max_hosts`. Check exact IP/CIDR/domain and `excludes`. |
| `TOOL_FAILED` with no stdout | Binary missing (local mode), target unreachable/filtered, or parser rejected the output. Check `stderr.txt` and `result.json`. |
| `JOB_LIMIT` | Global or per-task concurrency cap reached; wait or `job_cancel`. |
| `NOT_IMPLEMENTED` | SNMPv3 or Phase 2 credential features; Phase 1 runs v1/v2c anonymously. |
| `full_tcp` / `syn` / `os_detect` / `axfr` blocked | An intercept rule is asking for approval. Approve it, or choose a narrower profile. SYN/OS also need scope policy and `NET_RAW`. |
| Artifacts absent | `ARTIFACT_ROOT` not mounted writable, wrong permissions, or the job has not finished. |
| MCP tools not visible in ARTEX | Server name must be `kali_runner`, the server must be enabled, and `network-recon` must be loaded/visible for the agent. |
| `docker compose` says the service is not running | The profile is opt-in; add `--profile nonweb`. |
| Scope file exists but calls fail after editing | The runner caches scope for 5 seconds; wait or restart the runner. |

---

## 11. Security notes and limitations

### Boundaries

- **No generic command endpoint.** The tool surface is fixed; arguments are
  validated by typed models and converted to fixed argv.
- **Scope is enforced by the runner, not the prompt.** A compromised or
  confused agent cannot widen the signed scope.
- **Default deny.** Missing, expired, tampered, or task-mismatched scope files
  are rejected. Always-blocked ranges cannot be overridden by a scope.
- **Isolation.** The runner has no database credentials, no ARTEX API token,
  and is not attached to the default Compose network, so it has no direct route
  to Postgres.
- **Hardening.** The Compose service runs read-only, non-root UID 10001, drops
  all capabilities, and has PID/memory/CPU limits. SYN/OS detection needs
  `NET_RAW` explicitly added.
- **No host port.** `expose` keeps `8899` container-internal; it is reachable on
  the Compose networks but not published to the host. Only publish it to
  localhost for standalone testing.
- **Untrusted output.** Target banners and service output are untrusted.
  ARTEX appends its MCP untrusted note; the agent must record suspicious text
  as evidence, not follow it.

### Phase 1 limitations

- Compose is not a firewall. For client work, run the runner in a dedicated
  VM or network namespace with an egress allowlist.
- Jobs are in memory; a restart loses in-flight work (artifacts remain).
- Only `ip` and `service` observations are ingested. DNS, TLS, SMB, LDAP, SNMP,
  and SSH details are returned to the model and stored in artifacts.
- SMB/LDAP are anonymous; credentials are not modeled yet.
- Artifacts live under the task data directory and are visible to the file
  manager. Phase 2 should move sensitive captures to a restricted path.
- One runner should serve one client. Never give a single runner a union of
  unrelated scopes.

---

## 12. File map

| Path | Purpose |
| --- | --- |
| `runner/runner/server.py` | FastMCP app, bearer auth, body limit, `/healthz` |
| `runner/runner/config.py` | Environment parsing and startup validation |
| `runner/runner/scope.py` | Scope loading, HMAC verification, target matching, blocked ranges |
| `runner/runner/jobs.py` | Job registry, concurrency, timeout, process-group kill |
| `runner/runner/tools/net.py` | Tool contracts, command construction, parsers |
| `runner/runner/artifacts.py` | Atomic writes, manifests, SHA-256, size caps |
| `runner/runner/sanitize.py` | ANSI/control stripping and truncation |
| `runner/runner/errors.py` | Structured error codes |
| `runner/runner/envelope.py` | Bounded model-facing envelope |
| `runner/README.md` | Full operator runbook and configuration reference |
| `server/scopeexport.go` | Signed scope exporter and 30-second reconciler |
| `db/scope_snapshot.go` | Task/company scope read model |
| `agent/observations.go` | Envelope ingestion and `ip`/`service` persistence |
| `skills/network-recon/SKILL.md` | Skill gates, tool selection, recipes |
| `docker-compose.yml` | `nonweb` profile, control/engagement networks, hardening |
| `.env.example` | Runner token/key and scope directory entries |
| `docs/non-web-capability-runner.md` | Authoritative Phase 1 specification |

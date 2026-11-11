# ARTEX — Windows / Docker setup guide

How this checkout is wired together, and how to start, stop, rebuild and
troubleshoot it on a single-operator Windows machine. It documents the *setup*,
not any particular engagement; task data and results live in your database and
under `data/`, and stay there.

Last verified: **2026-11-05** (Europe/Oslo).

---

## Start it

Double-click **`ARTEX START.cmd`**.

Takes ~11s if Docker is already running, ~40s if Docker Desktop is stopped.
It handles every state on its own — you do not need to start Docker first.

| I want to… | Do this |
|---|---|
| Start normally | Double-click `ARTEX START.cmd` |
| Start, keep browser closed | `.\artex-up.ps1 -NoBrowser` |
| Start and watch logs | `.\artex-up.ps1 -Logs` |
| Stop, keep all data | `.\artex-down.ps1` |
| Stop and wipe the database | `.\artex-down.ps1 -Purge` |

Then open **http://127.0.0.1:8787**.

> PowerShell blocking the scripts is expected on a fresh shell. The `.cmd`
> wrapper bypasses it for that one run without changing any system policy.
> From a terminal: `powershell -NoProfile -ExecutionPolicy Bypass -File .\artex-up.ps1`

Login is **off by default** in this checkout (see
[Login modes](#login-modes)); set `ARTEX_REQUIRE_AUTH=1` to restore the password
login, in which case the session signing key in `keys\jwt.key` keeps you signed in
across restarts and rebuilds.

---

## What is running

| Container | Image | Ports |
|---|---|---|
| `artex-artex-1` | `artex:local` (built locally from this checkout) | `127.0.0.1:8787` UI, `127.0.0.1:8788` proxy |
| `artex-postgres-1` | `postgres:16-alpine` | internal only |

Both bind to **loopback only** — not reachable from other machines on your network.

**Engine config:** 3 concurrent workers, listening on `:8787`, proxy on `:8788`,
data directory `/app/data` (mapped to `.\data`).

---

## Login modes

The app ships with password login **off**, so the UI opens directly. What still
protects it:

- **Loopback-only binding** — `docker-compose.yml` publishes both ports on
  `127.0.0.1`. Never set `ARTEX_BIND_ADDR=0.0.0.0`.
- **`ARTEX_NOAUTH_CIDRS`** (default `127.0.0.0/8,::1/128`) — no-auth is honoured
  only for peers inside these ranges; anything else gets `401`.
- **Origin/Host check** — cross-site writes are rejected in no-auth mode.
- **`X-ARTEX-Mode`** on every response — `noauth` or `auth`, answerable by one `curl`.

To restore the original password login, set `ARTEX_REQUIRE_AUTH=1` and recreate
the container. There is no code change involved.

> **Understand what no-auth means.** The ARTEX API is not read-only: it can write
> workspace files, register custom tools (arbitrary commands in the container),
> rewrite agent prompts, and launch autonomous agents that run nmap, sqlmap and
> nuclei. With login off it is trusted local software, not a hardened service.
> Keep it on loopback, and turn login back on if you ever expose it.

---

## LLM configuration

The LLM is configured **in the database**, not in `.env`. This is the important
part to understand.

| Setting | Value |
|---|---|
| Profile name | `prod` |
| Format | `openai` — "OpenAI (Chat Completions)" |
| Base URL | `https://openrouter.ai/api/v1` |
| Model | `z-ai/glm-5.3-flash` |
| Active | yes (`is_default = true`) |
| Rate limits | 2 requests/sec, 60 requests/min |
| Context window | 200K |
| Streaming | on |
| API key | stored in the database |

Any OpenAI-compatible gateway works (OpenRouter, Routeway, a local Ollama).

### Why `.env` has blank API keys

`OPENAI_API_KEY` and `ANTHROPIC_API_KEY` in `.env` are **intentionally empty**.
When a profile exists in the database it takes precedence — the startup log
shows `LLM configured from DB: <format> / <model>`. Filling in those variables
would have no effect.

The only value `.env` genuinely needs is `POSTGRES_PASSWORD`.

### Changing the model

UI → **System → LLM**. Edit the `prod` profile or add a new one.

Two things that trip people up:

1. **New profiles save inactive.** Click **"Set as active"** on the profile
   card, or the engine stays idle with `[engine] no LLM provider configured`.
2. **Format must match the gateway, not the model.** OpenRouter and Routeway
   both need `openai` (Chat Completions). Choosing "OpenAI (Responses API)"
   appends `/responses`, which neither gateway implements → 404 on first call.
   Routing to a Claude model *through OpenRouter* still uses `openai`.

---

## Scope is per-task, and the agent extends it

Each task records its own scope rows. Root domains you name are recorded as
`root_domain`; the agent then adds discovered `subdomain` and `ip` entries marked
`source = auto`, and occasionally adds a row itself with `source = agent` and a
written justification.

That last part deserves attention: in practice the agent has added a
third-party host (a hosted-backend subdomain hardcoded in the target's
frontend) to scope, reasoning it was "the backend API endpoint hardcoded in the
target's frontend code." That is a defensible reading of scope, but it means
**the agent can widen its own scope**. Review the Scope section of each task
before treating a run as complete — and remember that authorization for a target
does not extend to someone else's backend it happens to call.

---

## ScopeSentry — optional, runs alongside

ScopeSentry is an independent asset-collection system. The integration in this
setup is **configured but switched off**: ARTEX has an MCP server entry named
`ScopeSentry` (transport `http`) and a `browser` entry (`npx` stdio), and both
are disabled, so ARTEX is not calling ScopeSentry tools. The `scopesentry` skill
is installed and available to the agent as documentation regardless.

To connect them: UI → **System → MCP**, set the URL on the `ScopeSentry` entry
to `http://host.docker.internal:<port>` with a ScopeSentry API key, and enable
it. It must be `host.docker.internal`, not `127.0.0.1` — inside the ARTEX
container `127.0.0.1` is the container itself. A row with an empty URL does
nothing when enabled.

---

## Capabilities in the image

Available to the agent inside the container:

- **Recon:** nuclei v3.11.1, subfinder v2.17.0, httpx, katana, ffuf 2.3.0,
  nmap 7.93, bbot 3.0.2 (142 modules), sqlmap
- **Exploit/scan:** dalfox 3.2.4, ripgrep 13
- **Browser:** Playwright with chromium-1248
- **Skills (11):** `api-recon`, `api-security`, `bbot-recon`, `codeaudit`,
  `edr-bypass-re`, `network-recon`, `patch-diff`, `php2shell`, `playwright-cli`,
  `rea`, `scopesentry`

The optional `kali-runner` (the `nonweb` Compose profile) adds typed network
tools — nmap, DNS, TLS, SNMP, SMB, LDAP, SSH — gated by a per-task HMAC-signed
scope file. See [`runner/HOW-IT-WORKS.md`](runner/HOW-IT-WORKS.md).

---

## Where state lives

| Location | Contents | Survives stop? | Survives `-Purge`? |
|---|---|---|---|
| Docker volume `artex_pgdata` | tasks, findings, assets, users, LLM profile | yes | **no** |
| `.\data\transcripts` | agent transcripts | yes | yes |
| `.\data\tasks` | task working files | yes | yes |
| `.\data\traffic` | captured proxy traffic | yes | yes |
| `.\keys\jwt.key` | session signing key | yes | yes |
| `.\skills\` | loaded live from host, no rebuild needed | yes | yes |
| `.\.env` | DB password | yes | yes |

`data/`, `keys/`, and `skills/` are host bind mounts, so they are real Windows
folders — easy to back up. Only the Postgres volume is Docker-managed.

> `data/` is an operational store: it holds target data and evidence. It is
> gitignored, and must stay that way. Never commit it.

---

## Rebuilding

Only needed after a `git pull` that changes Go or UI source. Normal start/stop
never rebuilds.

```powershell
docker compose -f docker-compose.yml build artex
.\artex-up.ps1
```

Expect ~10–20 minutes. The build needs several GB of free disk.

### The `Dockerfile` bbot patch

The `Dockerfile` carries one local patch (bbot dependency install retry,
~line 98). Upstream's bbot stage installs ~142 module dependencies; one flaky
failure poisons bbot's config, the next line refuses to retry, and the build
exits 1. It is patched to reset config and retry once:

```sh
bbot -y --install-all-deps || { rm -rf /root/.config/bbot; bbot -y --install-all-deps; }
```

A `git pull` or `git checkout` may overwrite it. If an image rebuild fails at
the bbot stage with `Skipping dependency install for module ... because it failed
previously`, re-apply it.

---

## Troubleshooting

**Launcher says a port is held.** Something else owns 8787/8788 — often a
leftover native build. `Get-NetTCPConnection -LocalPort 8787` shows the PID.

**UI loads but the engine does nothing.** No active LLM profile. Check the
launcher's `LLM profile` section, or UI → System → LLM → "Set as active".

**LLM calls fail with 404.** Wrong format — "OpenAI (Responses API)" selected
against OpenRouter. Switch to "OpenAI (Chat Completions)".

**LLM calls fail with 402 / quota.** OpenRouter account balance.

**Container restart-loops on boot with `database system is starting up`.**
Harmless — Postgres is slower than the app. It retries; the launcher's `--wait`
usually prevents this.

**Forgot the UI password.** `.\reset-password.sh` exists upstream for the native
build; for the Docker setup, the hash lives in the `settings` table under
`auth.password_hash`.

**A remote client gets 401 in no-auth mode.** The peer is outside
`ARTEX_NOAUTH_CIDRS`. Either reach it over loopback (SSH tunnel, reverse proxy)
or deliberately widen the CIDRs.

---

## Ground rules

Only point tasks at systems you are **authorized to test**: your own lab, your
organization's assets, or a program's published in-scope targets, within its
rules of engagement. That authorization does not extend to anything the agent
discovers, including third-party services the target's frontend calls.

Keep a written record of authorization per engagement. An autonomous agent
running unsolicited CVE exploitation against a live file-upload endpoint is
attacker-shaped work even when your intent is defensive, and you will want the
paper trail.

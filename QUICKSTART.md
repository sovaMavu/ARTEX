# ARTEX — quick start (Windows / Docker)

Double-click **`ARTEX START.cmd`**. That's it.

It works from any state: Docker Desktop not running, containers stopped,
half-started, or already running. Takes ~40s cold (Docker Desktop not started)
or ~11s warm.

## What the launcher does

1. Starts Docker Desktop if the engine isn't answering, waits for it.
2. Checks `.env` has `POSTGRES_PASSWORD` (fails early with a clear message).
3. Checks ports 8787/8788 aren't held by some other process.
4. Runs `docker compose up -d --wait`, retrying once if first-boot DB init trips it.
5. Polls `/api/health` until the app actually responds.
6. Reports whether an **active** LLM profile is set — the engine is idle without one.

## Commands

| Task | Command |
|---|---|
| Start (terminal) | `.\artex-up.ps1` |
| Start without opening browser | `.\artex-up.ps1 -NoBrowser` |
| Start and follow logs | `.\artex-up.ps1 -Logs` |
| Stop, keep all data | `.\artex-down.ps1` |
| Stop and wipe the database | `.\artex-down.ps1 -Purge` |

If PowerShell blocks the scripts:
`powershell -NoProfile -ExecutionPolicy Bypass -File .\artex-up.ps1`
(The `.cmd` wrapper already does this for you.)

## URLs

| Service | URL |
|---|---|
| Web UI | http://127.0.0.1:8787 |
| Traffic recording proxy | http://127.0.0.1:8788 |
| Health check | http://127.0.0.1:8787/api/health |

Both ports bind to `127.0.0.1` only — not reachable from other machines.

## Login

Login is **off** in this checkout: the UI opens directly. Peers outside
`ARTEX_NOAUTH_CIDRS` (loopback by default) still get `401`, cross-site writes are
rejected, and every response carries `X-ARTEX-Mode: noauth`. Set
`ARTEX_REQUIRE_AUTH=1` in `.env` to restore the original password login.

Because the ARTEX API can write files and run commands inside the container,
no-auth mode is only appropriate for loopback, single-operator use.

## Current configuration

- **LLM profile:** `prod` — format `openai` (Chat Completions), model
  `z-ai/glm-5.3-flash`, base URL `https://openrouter.ai/api/v1`, rate limits
  2 req/s and 60 req/min, 200K context.
- **Workers:** 3 concurrent agents.
- **Postgres:** inside the `pgdata` volume.

**For the full picture of this setup** — how it is wired together, login modes,
LLM configuration, and the local Dockerfile patch — see
[`SETUP.md`](SETUP.md).

## Where state lives

| Path | Contents | Survives rebuild? |
|---|---|---|
| Postgres volume `artex_pgdata` | tasks, findings, assets, users, LLM profiles | yes, until `-Purge` |
| `data\` | task files, transcripts, traffic captures | yes (host bind mount) |
| `keys\jwt.key` | signing key — keeps you logged in with auth on | yes (host bind mount) |
| `skills\` | loaded live, no rebuild needed | yes (host bind mount) |
| `.env` | DB password, optional LLM env vars | yes |

`.env` has blank LLM keys — that's intentional. The LLM is configured in the
database via the UI, which takes precedence.

`data/` contains target data and evidence. It is gitignored; keep it that way.

## Notes

- The `data` mount is Windows-side (e.g. `<checkout>\data`). Avoid editing files
  inside it while ARTEX is running.
- `docker-compose.yml` builds from this checkout as `artex:local`. Rebuilding is
  only needed after a `git pull` touching Go/UI source:
  `docker compose -f docker-compose.yml build artex`
- The `Dockerfile` has one local patch (bbot dependency-install retry, ~line 98).
  A `git pull` may overwrite it; re-apply if the image build fails at bbot.
- Docker Desktop does **not** start at login on this machine. The launcher
  handles that, but it means ARTEX won't come back on its own after a reboot —
  it waits for you to double-click.

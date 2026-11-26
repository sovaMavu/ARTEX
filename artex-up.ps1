<#
.SYNOPSIS
    One-click ARTEX launcher. Brings the whole stack up from a cold machine
    (Docker not even running) to a ready web UI.

.DESCRIPTION
    Idempotent: safe to run repeatedly, whether ARTEX is stopped, running,
    half-broken, or Docker Desktop is not started.

    It handles, in order:
      1. Docker Desktop not running            -> starts it, waits for engine
      2. A different Docker context selected   -> switches to desktop-linux
      3. Ports 8787/8788 already taken         -> reports the owner, aborts
      4. Containers stopped / unhealthy        -> docker compose up -d --wait
      5. LLM profile missing or unset          -> warns loudly, with fix steps
      6. Readiness                            -> polls /api/health until OK

.PARAMETER NoBrowser
    Do not open the UI in the default browser.

.PARAMETER Logs
    Attach to the artex container's log stream after it is up (Ctrl-C detaches).

.EXAMPLE
    .\artex-up.ps1
    .\artex-up.ps1 -Logs
#>
[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [switch]$Logs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- constants -------------------------------------------------------------
$RepoRoot      = $PSScriptRoot
$ComposeFile   = Join-Path $RepoRoot 'docker-compose.yml'
$EnvFile       = Join-Path $RepoRoot '.env'
$UiUrl         = 'http://127.0.0.1:8787'
$HealthUrl     = 'http://127.0.0.1:8787/api/health'
$ProxyUrl      = 'http://127.0.0.1:8788'
$DockerDesktop = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
$RequiredPorts = @(8787, 8788)

# --- pretty output ---------------------------------------------------------
function Write-Step    { param([string]$Message) Write-Host "`n[$([char]0x25B6)] $Message" -ForegroundColor Cyan }
function Write-Ok      { param([string]$Message) Write-Host "    OK   $Message" -ForegroundColor Green }
function Write-Warn    { param([string]$Message) Write-Host "    WARN $Message" -ForegroundColor Yellow }
function Write-Fail    { param([string]$Message) Write-Host "    FAIL $Message" -ForegroundColor Red }
function Write-Info    { param([string]$Message) Write-Host "         $Message" -ForegroundColor DarkGray }

function Write-Banner {
    Write-Host @'

   _    ____ _____ _______  __
  / \  |  _ \_   _| ____\ \/ /
 / _ \ | |_) || | |  _|  \  /
/ ___ \|  _ < | | | |___ /  \
/_/   \_\_| \_\|_| |_____/_/\_\   launcher
'@ -ForegroundColor Magenta
}

# --- helpers ---------------------------------------------------------------

# Return $true if the Docker engine answers. Never throws.
function Test-DockerEngine {
    try {
        $null = & docker info --format '{{.ServerVersion}}' 2>&1
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

# Block until the Docker engine answers, or throw on timeout.
function Wait-DockerEngine {
    param([int]$TimeoutSeconds = 180)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $spinner  = @('|', '/', '-', '\')
    $i = 0

    while ((Get-Date) -lt $deadline) {
        if (Test-DockerEngine) {
            Write-Host "`r    OK   Docker engine is up.            " -ForegroundColor Green
            return
        }
        Write-Host ("`r    ..   waiting for Docker engine {0}" -f $spinner[$i % 4]) -NoNewline -ForegroundColor DarkGray
        $i++
        Start-Sleep -Seconds 2
    }
    Write-Host ''
    throw "Docker engine did not become ready within $TimeoutSeconds seconds."
}

# Make sure the engine is reachable; start Docker Desktop if it is not.
function Ensure-Docker {
    Write-Step 'Docker engine'

    if (Test-DockerEngine) {
        Write-Ok 'already running'
        return
    }

    Write-Info 'engine not reachable - starting Docker Desktop'

    if (-not (Test-Path $DockerDesktop)) {
        throw "Docker Desktop not found at '$DockerDesktop'. Install it or start your Docker engine manually."
    }

    if (-not (Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue)) {
        Start-Process -FilePath $DockerDesktop | Out-Null
        Write-Info 'Docker Desktop launched'
    } else {
        Write-Info 'Docker Desktop process found but engine down - waiting for it'
    }

    # A first cold start (VM boot) can take a couple of minutes.
    Wait-DockerEngine -TimeoutSeconds 240

    # The wrong context is a classic silent failure.
    $ctx = (& docker context show 2>&1 | Out-String).Trim()
    if ($ctx -ne 'desktop-linux') {
        Write-Info "context is '$ctx' - switching to desktop-linux"
        & docker context use desktop-linux *> $null
        if (-not (Test-DockerEngine)) {
            throw 'Docker engine still unreachable after switching context.'
        }
    }
    Write-Ok 'engine ready'
}

# Validate .env early with a clear message instead of a cryptic compose error.
function Assert-EnvFile {
    Write-Step '.env'

    if (-not (Test-Path $EnvFile)) {
        throw ".env is missing at '$EnvFile'. Copy .env.example to .env and set POSTGRES_PASSWORD."
    }

    $content = Get-Content -LiteralPath $EnvFile -Raw
    if ($content -notmatch '(?m)^\s*POSTGRES_PASSWORD\s*=\s*\S') {
        throw 'POSTGRES_PASSWORD is missing or empty in .env - compose will refuse to start.'
    }
    Write-Ok '.env present and has POSTGRES_PASSWORD'
}

# Abort if another process owns a port we need (e.g. a leftover native artex.exe).
function Assert-PortsFree {
    Write-Step 'Ports'

    $busy = @()
    foreach ($port in $RequiredPorts) {
        $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
                Select-Object -First 1
        if (-not $conn) { continue }

        $procId   = $conn.OwningProcess
        $procName = 'unknown'
        try {
            $procName = (Get-Process -Id $procId -ErrorAction Stop).ProcessName
        } catch { }

        # com.docker.backend / vpnkit publishing our own container is fine.
        if ($procName -match 'com\.docker|docker|vpnkit|wslrelay') {
            Write-Ok "port $port held by Docker ($procName) - expected"
            continue
        }

        $busy += "port $port held by $procName (PID $procId)"
    }

    if ($busy.Count -gt 0) {
        $detail = ($busy -join '; ')
        throw "Port conflict: $detail. Stop that process, or change ARTEX_BIND_ADDR in .env."
    }

    if ($busy.Count -eq 0) { Write-Ok 'ports 8787 and 8788 available' }
}

# Run a native command and return everything it wrote (stdout + stderr) as
# plain strings, without tripping $ErrorActionPreference = 'Stop'.
#
# `docker compose` writes ordinary progress ("Container x Healthy") to stderr.
# Windows PowerShell 5.1 replies to ANY native stderr by raising a
# NativeCommandError, and that record propagates out of the function as a
# non-terminating error the caller's catch block never sees — 2>&1 and *>file
# both still go through PowerShell's stream machinery, so neither helps.
#
# The reliable way is to bypass that machinery: use System.Diagnostics.Process
# with RedirectStandardError set to false so the child inherits the console's
# stderr handle and PowerShell never sees it. stdout is captured separately.
function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $FilePath
    $psi.Arguments              = ($ArgumentList | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true    # captured here, never enters PS streams
    $psi.CreateNoWindow         = $true
    $psi.WorkingDirectory       = (Get-Location).Path

    $proc = [System.Diagnostics.Process]::Start($psi)
    # Read both streams asynchronously to avoid a deadlock on large output.
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    $out = $outTask.GetAwaiter().GetResult()
    $err = $errTask.GetAwaiter().GetResult()

    $all = @($out, $err) -join "`n"
    return [pscustomobject]@{
        ExitCode = $proc.ExitCode
        Output   = $out
        Error    = $err
        Lines    = @($all -split "`r?`n" | Where-Object { $_.Trim() })
    }
}

# Bring the compose stack up, restarting anything not healthy.
function Start-Stack {
    Write-Step 'Starting stack'

    Push-Location $RepoRoot
    try {
        # --wait blocks until healthchecks pass (postgres) and containers are up.
        $r = Invoke-NativeCapture docker @('compose', '-f', $ComposeFile, 'up', '-d', '--wait')
        foreach ($line in $r.Lines) { Write-Host "         $line" -ForegroundColor DarkGray }
        $code = $r.ExitCode
    } finally {
        Pop-Location
    }

    if ($code -ne 0) {
        Write-Warn "compose exited with code $code - retrying once (first-boot DB init can trip --wait)"

        Push-Location $RepoRoot
        try {
            Start-Sleep -Seconds 5
            $r2 = Invoke-NativeCapture docker @('compose', '-f', $ComposeFile, 'up', '-d')
            foreach ($line in $r2.Lines) { Write-Host "         $line" -ForegroundColor DarkGray }
        } finally {
            Pop-Location
        }
    }

    # Report what actually happened. `compose ps --format json` emits one JSON
    # object per line with PascalCase keys (Service/State/Health), so read it
    # defensively: a parse failure here must never fail the launch.
    try {
        $ps = Invoke-NativeCapture docker @('compose', '-f', $ComposeFile, 'ps', '--format', 'json')
        foreach ($line in $ps.Lines) {
            if (-not $line.Trim()) { continue }
            try {
                $svc = $line | ConvertFrom-Json
                $name = $svc.PSObject.Properties['Service'].Value
                $st   = $svc.PSObject.Properties['State'].Value
                $hlth = $svc.PSObject.Properties['Health'].Value
                if (-not $name) { continue }
                $desc = if ($hlth) { "$st ($hlth)" } else { "$st" }
                if ($st -eq 'running') {
                    Write-Ok  "$name : $desc"
                } else {
                    Write-Warn "$name : $desc"
                }
            } catch {
                # Non-JSON or unexpected shape - fall back to the raw line.
                Write-Info $line.Trim()
            }
        }
    } catch {
        Write-Info 'could not summarise container state (non-fatal)'
    }
}

# Poll the health endpoint until the app answers.
function Wait-AppReady {
    param([int]$TimeoutSeconds = 120)

    Write-Step 'Readiness'

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 5
            if ($r.ok) {
                Write-Ok "health endpoint OK (version $($r.version))"
                return $true
            }
        } catch { }
        Start-Sleep -Seconds 2
    }

    Write-Fail "no healthy response at $HealthUrl within $TimeoutSeconds s"
    Write-Info 'recent logs:'
    & docker logs artex-artex-1 --tail 25 2>&1 | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }
    return $false
}

# Confirm an LLM profile exists and is marked default - the engine is idle without one.
function Test-LlmProfile {
    Write-Step 'LLM profile'

    $query = "SELECT id, name, format, model, base_url, is_default, rate_per_second, rate_per_minute, context_window_k FROM llm_profiles ORDER BY id;"
    $raw = & docker exec artex-postgres-1 psql -U artex -d artex -Atc $query 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Warn 'could not read llm_profiles from Postgres'
        return $false
    }

    $rows = @($raw | Where-Object { $_ -and $_.Trim() })
    if ($rows.Count -eq 0) {
        Write-Warn 'no LLM profile configured - the engine will stay idle.'
        Write-Info 'Open the UI -> System -> LLM -> New model profile'
        Write-Info 'Format: OpenAI (Chat Completions); Base URL: https://openrouter.ai/api/v1'
        Write-Info 'Then click "Set as active" on the profile card.'
        return $false
    }

    $active = $false
    foreach ($row in $rows) {
        $f = $row -split '\|'
        if ($f.Count -lt 6) { continue }
        $isDefault = $f[5] -eq 't'
        if ($isDefault) { $active = $true }
        $mark = if ($isDefault) { 'active  ' } else { 'inactive' }
        Write-Host ("         {0} | {1} | {2} | {3} | {4} | rps={5} rpm={6} ctx={7}K" -f `
            $mark, $f[0], $f[1], $f[2], $f[3], $f[6], $f[7], $f[8]) -ForegroundColor Gray
    }

    if ($active) {
        Write-Ok 'an active profile is set'
        return $true
    }

    Write-Warn 'profiles exist but none is active - engine stays idle until you click "Set as active"'
    return $false
}

function Get-ContainerStatus {
    $j = & docker inspect artex-artex-1 2>$null | ConvertFrom-Json
    if (-not $j) { return $null }
    return [pscustomobject]@{
        Status    = $j[0].State.Status
        Restarts  = $j[0].RestartCount
        StartedAt = $j[0].State.StartedAt
    }
}

# --- main ------------------------------------------------------------------
Write-Banner

$hadError = $false
try {
    Ensure-Docker
    Assert-EnvFile
    Assert-PortsFree
    Start-Stack

    if (-not (Wait-AppReady)) { $hadError = $true }
    $llmOk = Test-LlmProfile

    # Summary
    Write-Host ("`n" + ('-' * 62)) -ForegroundColor DarkGray
    $st = Get-ContainerStatus
    if ($st) {
        Write-Host ("  artex container : {0} (restarts: {1})" -f $st.Status, $st.Restarts) -ForegroundColor Gray
    }
    Write-Host ("  UI              : {0}" -f $UiUrl)   -ForegroundColor White
    Write-Host ("  traffic proxy   : {0}" -f $ProxyUrl) -ForegroundColor Gray
    Write-Host ("  LLM             : {0}" -f $(if ($llmOk) { 'ready' } else { 'NOT READY - see above' })) `
        -ForegroundColor $(if ($llmOk) { 'Green' } else { 'Yellow' })
    Write-Host ('-' * 62) -ForegroundColor DarkGray

    if ($hadError) {
        Write-Host "`nARTEX is up but did not report healthy. Check: docker logs artex-artex-1`n" -ForegroundColor Red
        exit 1
    }

    Write-Host "`nARTEX is ready.`n" -ForegroundColor Green

    if (-not $NoBrowser) { Start-Process $UiUrl | Out-Null }

    if ($Logs) {
        Write-Host 'Attaching to logs (Ctrl-C to detach; the stack keeps running).' -ForegroundColor DarkGray
        & docker logs -f artex-artex-1
    }

    exit 0
} catch {
    Write-Host ''
    Write-Fail $_.Exception.Message
    Write-Host "`nNothing was destroyed. Fix the problem above and re-run .\artex-up.ps1`n" -ForegroundColor Yellow
    exit 1
}

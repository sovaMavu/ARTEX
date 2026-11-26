<#
.SYNOPSIS
    Restore ARTEX from this portable bundle onto any Windows machine with
    Docker Desktop installed.

.DESCRIPTION
    Run this from inside the bundle folder:

        .\restore.ps1

    It will:
      1. Start Docker Desktop if it is not running
      2. Load the 1.7 GB container image
      3. Create .env from machine.env
      4. Start Postgres and import the database dump
      5. Start ARTEX and confirm it is healthy

    Everything - tasks, findings, assets, users, the LLM profile and its API
    key - comes back exactly as it was. You stay logged in.

.PARAMETER SkipData
    Do not overwrite the data/ folder copies. Use when re-running a restore.

.EXAMPLE
    .\restore.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipDatabaseRestore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Here     = $PSScriptRoot
$ImageTar = Join-Path $Here 'artex-image.tar.gz'
$DbDump   = Join-Path $Here 'artex-db.sql.gz'
$EnvFile  = Join-Path $Here '.env'
$Compose  = Join-Path $Here 'docker-compose.yml'
$UiUrl    = 'http://127.0.0.1:8787'

function Step { param($m) Write-Host "`n[$([char]0x25B6)] $m" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "    OK   $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "    WARN $m" -ForegroundColor Yellow }
function Fail { param($m) Write-Host "    FAIL $m" -ForegroundColor Red }
function Info { param($m) Write-Host "         $m" -ForegroundColor DarkGray }

# Native capture that survives PowerShell 5.1's NativeCommandError behaviour.
function Invoke-Native {
    param([string]$FilePath, [string[]]$ArgumentList)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = ($ArgumentList | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"','\"') + '"' } else { $_ }
    }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = (Get-Location).Path
    $proc = [System.Diagnostics.Process]::Start($psi)
    $o = $proc.StandardOutput.ReadToEndAsync()
    $e = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    [pscustomobject]@{ ExitCode=$proc.ExitCode; Out=$o.GetAwaiter().GetResult(); Err=$e.GetAwaiter().GetResult() }
}

Write-Host @'

   _    ____ _____ _______  __
  / \  |  _ \_   _| ____\ \/ /
 / _ \ | |_) || | |  _|  \  /
/ ___ \|  _ < | | | |___ /  \
/_/   \_\_| \_\|_| |_____/_/\_\   restore
'@ -ForegroundColor Magenta

try {
    # ---------------------------------------------------------------- checks
    Step 'Checking bundle'
    foreach ($f in @($ImageTar, $DbDump, $Compose, (Join-Path $Here 'machine.env'))) {
        if (-not (Test-Path $f)) { throw "Bundle is incomplete - missing $(Split-Path $f -Leaf)" }
    }
    Ok 'all files present'

    # ---------------------------------------------------------------- docker
    Step 'Docker engine'
    $probe = Invoke-Native docker @('info','--format','{{.ServerVersion}}')
    if ($probe.ExitCode -ne 0) {
        Info 'engine not running - starting Docker Desktop'
        $dd = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
        if (-not (Test-Path $dd)) {
            throw 'Docker Desktop is not installed. Install it first: https://www.docker.com/products/docker-desktop/'
        }
        if (-not (Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue)) {
            Start-Process $dd | Out-Null
        }
        $deadline = (Get-Date).AddSeconds(300)
        while ((Get-Date) -lt $deadline) {
            $p = Invoke-Native docker @('info','--format','{{.ServerVersion}}')
            if ($p.ExitCode -eq 0) { break }
            Write-Host "    ..   waiting for engine" -ForegroundColor DarkGray
            Start-Sleep -Seconds 3
        }
        if ((Invoke-Native docker @('info')).ExitCode -ne 0) { throw 'Docker engine did not start.' }
    }
    Ok 'engine ready'

    # ---------------------------------------------------------------- image
    Step 'Loading image (1.7 GB - this takes a few minutes)'
    Push-Location $Here
    try {
        $r = Invoke-Native docker @('load','-i',$ImageTar)
        if ($r.ExitCode -ne 0) { throw "docker load failed: $($r.Err)" }
    } finally { Pop-Location }
    Ok 'image loaded as artex:local'

    # ---------------------------------------------------------------- env
    Step 'Writing .env'
    $me = Get-Content (Join-Path $Here 'machine.env') -Raw
    Set-Content -Path $EnvFile -Value $me.TrimEnd() -Encoding UTF8
    Ok '.env created from machine.env'

    # Read the DB credentials back out of .env so the import step matches them.
    $script:PgUser = 'artex'; $script:PgDb = 'artex'; $script:PgPassword = ''
    foreach ($line in ($me -split "`r?`n")) {
        if ($line -match '^\s*POSTGRES_USER\s*=\s*(\S+)')     { $script:PgUser     = $Matches[1] }
        if ($line -match '^\s*POSTGRES_DB\s*=\s*(\S+)')       { $script:PgDb       = $Matches[1] }
        if ($line -match '^\s*POSTGRES_PASSWORD\s*=\s*(\S+)') { $script:PgPassword = $Matches[1] }
    }
    if (-not $script:PgPassword) { throw 'machine.env has no POSTGRES_PASSWORD' }

    # ---------------------------------------------------------------- dirs
    foreach ($d in 'data','keys') {
        $p = Join-Path $Here $d
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }

    # ---------------------------------------------------------------- start pg
    Step 'Starting Postgres'
    Push-Location $Here
    try {
        $r = Invoke-Native docker @('compose','-f',$Compose,'up','-d','postgres')
        if ($r.ExitCode -ne 0) { throw "compose up failed: $($r.Err)" }

        # Wait for the healthcheck rather than sleeping blind.
        $deadline = (Get-Date).AddSeconds(120)
        $ready = $false
        while ((Get-Date) -lt $deadline) {
            $h = Invoke-Native docker @('inspect','--format','{{.State.Health.Status}}','artex-postgres-1')
            if ($h.Out.Trim() -eq 'healthy') { $ready = $true; break }
            Start-Sleep -Seconds 2
        }
        if (-not $ready) { throw 'Postgres did not become healthy.' }
    } finally { Pop-Location }
    Ok 'postgres healthy'

    # ---------------------------------------------------------------- restore db
    if (-not $SkipDatabaseRestore) {
        Step 'Restoring database'

        # Mount the bundle folder read-only into a staging volume and decompress
        # there. Works with no gzip/psql on the host. The import then runs in a
        # throwaway postgres container sharing the live server's network
        # namespace, so it can reach it without knowing the network name.
        $r = Invoke-Native docker @(
            'run','--rm',
            '-v',"${Here}:/bundle:ro",
            '-v','artex_restore:/staging',
            'alpine','sh','-c',
            'cp /bundle/artex-db.sql.gz /staging/ && cd /staging && gzip -df artex-db.sql.gz'
        )
        if ($r.ExitCode -ne 0) { throw "could not stage dump: $($r.Err)" }

        $r = Invoke-Native docker @(
            'run','--rm',
            '-v','artex_restore:/staging',
            '--network','container:artex-postgres-1',
            '-e','PGPASSWORD=' + $script:PgPassword,
            'postgres:16-alpine',
            'psql','-U',$script:PgUser,'-d',$script:PgDb,'-f','/staging/artex-db.sql'
        )
        if ($r.ExitCode -ne 0) { throw "database restore failed: $($r.Err)" }

        $null = Invoke-Native docker @('volume','rm','artex_restore','--force')
        Ok 'database restored'
    }

    # ---------------------------------------------------------------- start app
    Step 'Starting ARTEX'
    Push-Location $Here
    try {
        $r = Invoke-Native docker @('compose','-f',$Compose,'up','-d')
        if ($r.ExitCode -ne 0) { throw "compose up failed: $($r.Err)" }
    } finally { Pop-Location }

    $deadline = (Get-Date).AddSeconds(120)
    $healthy = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $h = Invoke-RestMethod -Uri "$UiUrl/api/health" -TimeoutSec 5
            if ($h.ok) { $healthy = $true; break }
        } catch { }
        Start-Sleep -Seconds 2
    }

    if (-not $healthy) {
        Fail 'ARTEX did not report healthy'
        Info 'logs:'
        (Invoke-Native docker @('logs','artex-artex-1','--tail','30')).Out -split "`n" |
            ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }
        throw 'restore incomplete'
    }
    Ok 'ARTEX healthy'

    # ---------------------------------------------------------------- summary
    Step 'Tally'
    $q = "SELECT 'profiles='||count(*) FROM llm_profiles; SELECT 'tasks='||count(*) FROM tasks; SELECT 'findings='||count(*) FROM findings; SELECT 'assets='||count(*) FROM assets;"
    $t = Invoke-Native docker @('exec','artex-postgres-1','psql','-U','artex','-d','artex','-tAc',$q)
    foreach ($line in ($t.Out -split "`n")) {
        if ($line.Trim()) { Info $line.Trim() }
    }

    Write-Host "`nARTEX restored. Open $UiUrl`n" -ForegroundColor Green
    Start-Process $UiUrl | Out-Null
    exit 0
} catch {
    Write-Host ''
    Fail $_.Exception.Message
    Write-Host "`nRe-run .\restore.ps1 after fixing the problem.`n" -ForegroundColor Yellow
    exit 1
}

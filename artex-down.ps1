<#
.SYNOPSIS
    Stop ARTEX (optionally with its database) without losing state.

.DESCRIPTION
    stop              -> stop containers, keep Postgres data. Start again instantly.
    -Purge            -> also delete the Postgres volume (wipes tasks, findings,
                         users, and LLM profiles). Asks for confirmation.

.PARAMETER Purge
    Remove the pgdata volume too. Destructive - requires typing YES.

.EXAMPLE
    .\artex-down.ps1
    .\artex-down.ps1 -Purge
#>
[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot    = $PSScriptRoot
$ComposeFile = Join-Path $RepoRoot 'docker-compose.yml'

function Write-Step  { param([string]$m) Write-Host "`n[$([char]0x25B6)] $m" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "    OK   $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "    WARN $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "    FAIL $m" -ForegroundColor Red }

# Run a native command capturing stdout+stderr as strings.
# Windows PowerShell 5.1 turns ANY native stderr output into a
# NativeCommandError that escapes a caller's catch block, and docker/compose
# write ordinary progress ("Container x Stopping") to stderr. Using Process
# with redirected handles keeps that text out of PowerShell's error stream.
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
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true
    $psi.WorkingDirectory       = (Get-Location).Path

    $proc = [System.Diagnostics.Process]::Start($psi)
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    $out = $outTask.GetAwaiter().GetResult()
    $err = $errTask.GetAwaiter().GetResult()

    $all = @($out, $err) -join "`n"
    return [pscustomobject]@{
        ExitCode = $proc.ExitCode
        Lines    = @($all -split "`r?`n" | Where-Object { $_.Trim() })
    }
}

try {
    $probe = Invoke-NativeCapture docker @('info', '--format', '{{.ServerVersion}}')
    if ($probe.ExitCode -ne 0) {
        Write-Warn 'Docker engine is not running - nothing to stop.'
        exit 0
    }

    Write-Step 'Stopping ARTEX'
    Push-Location $RepoRoot
    try {
        $r = Invoke-NativeCapture docker @('compose', '-f', $ComposeFile, 'stop')
        foreach ($line in $r.Lines) { Write-Host "         $line" -ForegroundColor DarkGray }
    } finally {
        Pop-Location
    }
    Write-Ok 'containers stopped (data preserved in the pgdata volume)'

    if ($Purge) {
        Write-Host "`n  This deletes the Postgres volume: tasks, findings, assets, logs," -ForegroundColor Red
        Write-Host "  users and LLM profiles are permanently lost." -ForegroundColor Red
        $answer = Read-Host "`n  Type YES to confirm"
        if ($answer -cne 'YES') {
            Write-Host "`n  Purge cancelled - containers remain stopped, data intact.`n" -ForegroundColor Yellow
            exit 0
        }

        Write-Step 'Removing volumes'
        Push-Location $RepoRoot
        try {
            $r = Invoke-NativeCapture docker @('compose', '-f', $ComposeFile, 'down', '-v')
            foreach ($line in $r.Lines) { Write-Host "         $line" -ForegroundColor DarkGray }
        } finally {
            Pop-Location
        }
        Write-Ok 'volume removed - next start is a clean first run'
        Write-Warn 'data\ and keys\ on disk were kept. Delete them manually for a full reset.'
    }

    Write-Host "`nStopped. Run .\artex-up.ps1 to start again.`n" -ForegroundColor Green
    exit 0
} catch {
    Write-Fail $_.Exception.Message
    exit 1
}

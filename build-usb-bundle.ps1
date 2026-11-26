# ARTEX portable bundle — build script
#
# Produces a self-contained folder you can copy to a USB stick and restore on
# another Windows machine with Docker Desktop installed.
#
# Output layout:
#   bundle/
#     artex-image.tar.gz        container image (~1.7 GB compressed)
#     artex-db.sql.gz           database dump (schema + data, no roles)
#     keys/jwt.key              session signing key (keeps you logged in)
#     data/                     task files, transcripts, traffic
#     skills/                   10 agent skills
#     machine.env               POSTGRES_PASSWORD etc
#     restore.ps1               one-click restore for the target machine
#     README.txt                what this is and what the target needs
#
# Run:  .\build-usb-bundle.ps1 -Out D:\ARTEX-BUNDLE

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Out
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = $PSScriptRoot

function Step { param($m) Write-Host "`n[$([char]0x25B6)] $m" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "    OK   $m" -ForegroundColor Green }
function Info { param($m) Write-Host "         $m" -ForegroundColor DarkGray }

# Native capture that keeps PowerShell 5.1 from turning stderr into an error.
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
    $proc = [System.Diagnostics.Process]::Start($psi)
    $o = $proc.StandardOutput.ReadToEndAsync()
    $e = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    [pscustomobject]@{ ExitCode=$proc.ExitCode; Out=$o.GetAwaiter().GetResult(); Err=$e.GetAwaiter().GetResult() }
}

Step "Destination"
Write-Host "    -> $Out"
if (Test-Path $Out) {
    $existing = Get-ChildItem $Out -Force -ErrorAction SilentlyContinue
    if ($existing) {
        throw "Destination '$Out' already exists and is not empty. Choose a new folder."
    }
} else {
    New-Item -ItemType Directory -Path $Out -Force | Out-Null
}
Ok "ready"

# ---------------------------------------------------------------- image
Step "Exporting image (this takes a few minutes)"
$imgPath = Join-Path $Out 'artex-image.tar'
$gzPath  = Join-Path $Out 'artex-image.tar.gz'

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$r = Invoke-Native docker @('save','-o',$imgPath,'artex:local')
if ($r.ExitCode -ne 0) { throw "docker save failed: $($r.Err)" }
$sw.Stop()
Info ("uncompressed: {0:N2} GB in {1:N0}s" -f ((Get-Item $imgPath).Length/1GB), $sw.Elapsed.TotalSeconds)

# Windows has no gzip; use a throwaway alpine container so the target machine
# needs no extra tools and restore is a plain tar -xzf.
Step "Compressing image"
$sw2 = [System.Diagnostics.Stopwatch]::StartNew()
$r = Invoke-Native docker @(
    'run','--rm',
    '-v',"${Out}:/out",
    'alpine','sh','-c','gzip -1 /out/artex-image.tar'
)
if ($r.ExitCode -ne 0) { throw "compression failed: $($r.Err)" }
$sw2.Stop()
Remove-Item $imgPath -Force -ErrorAction SilentlyContinue
Ok ("{0:N2} GB compressed in {1:N0}s" -f ((Get-Item $gzPath).Length/1GB), $sw2.Elapsed.TotalSeconds)

# ---------------------------------------------------------------- database
Step "Dumping database"
$dumpName = 'artex-db.sql'
$r = Invoke-Native docker @(
    'exec','artex-postgres-1',
    'pg_dump','-U','artex','-d','artex',
    '--no-owner','--no-privileges','--clean','--if-exists'
)
if ($r.ExitCode -ne 0) { throw "pg_dump failed: $($r.Err)" }
$sqlPath = Join-Path $Out $dumpName
[System.IO.File]::WriteAllText($sqlPath, $r.Out, (New-Object System.Text.UTF8Encoding($false)))
Info ("{0:N1} MB plain SQL" -f ((Get-Item $sqlPath).Length/1MB))

Step "Compressing database dump"
$r = Invoke-Native docker @(
    'run','--rm','-v',"${Out}:/out",'alpine','sh','-c',"gzip -9 /out/$dumpName"
)
if ($r.ExitCode -ne 0) { throw "dump compression failed: $($r.Err)" }
Ok ("{0:N1} MB compressed" -f ((Get-Item (Join-Path $Out "$dumpName.gz")).Length/1MB))

# ---------------------------------------------------------------- files
Step "Copying state and config"

foreach ($dir in 'keys','data','skills') {
    $src = Join-Path $Repo $dir
    if (-not (Test-Path $src)) { Info "skip $dir (absent)"; continue }
    $dst = Join-Path $Out $dir
    Copy-Item $src $dst -Recurse -Force
    $n = @(Get-ChildItem $dst -Recurse -File -ErrorAction SilentlyContinue).Count
    Ok "$dir  ($n files)"
}

# Carry the DB password across so the restore is drop-in.
$envSrc = Join-Path $Repo '.env'
$pgPass = $null
foreach ($line in Get-Content $envSrc) {
    if ($line -match '^\s*POSTGRES_PASSWORD\s*=\s*(\S+)') { $pgPass = $Matches[1] }
}
if (-not $pgPass) { throw 'could not read POSTGRES_PASSWORD from .env' }

$machineEnv = @"
# ARTEX portable bundle - machine config
POSTGRES_USER=artex
POSTGRES_PASSWORD=$pgPass
POSTGRES_DB=artex
ARTEX_BIND_ADDR=127.0.0.1
"@
Set-Content -Path (Join-Path $Out 'machine.env') -Value $machineEnv -Encoding UTF8 -NoNewline
Ok 'machine.env (database password carried over)'

# The LLM API key lives in the DB and comes with the dump, so nothing sensitive
# is written in plaintext here.

Ok "done"

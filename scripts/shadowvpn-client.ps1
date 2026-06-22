<#
.SYNOPSIS
    Launch the ShadowVPN client on Windows (self-elevating).

.DESCRIPTION
    Runs shadowvpn-client.exe with the given config. Creating the Wintun adapter
    and changing routes / DNS require Administrator, so this script relaunches
    itself elevated if it is not already.

    Stop it with Ctrl-C for a graceful shutdown: the system resolver is restored,
    the per-destination routes are removed, and the DNS cache is saved. A forced
    kill (Task Manager / `taskkill /F`) skips that cleanup and can leave the
    resolver pointed at the proxy.

.PARAMETER Config
    Path to the client JSON config. Default: client.json next to this script.

.PARAMETER Exe
    Path to shadowvpn-client.exe. Default: next to this script. wintun.dll must
    sit in the same folder as the exe (download it from https://www.wintun.net/).

.EXAMPLE
    .\shadowvpn-client.ps1
    Run with client.json from this folder.

.EXAMPLE
    .\shadowvpn-client.ps1 -Config C:\shadowvpn\client-chinadns.json
    Run policy routing in chinadns mode using the given config.
#>
[CmdletBinding()]
param(
    [string]$Config,
    [string]$Exe
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is an empty string inside param() default expressions under
# Windows PowerShell 5.1, so resolve the script folder here in the body (where it
# is populated) and apply the defaults.
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $Config) { $Config = Join-Path $here 'client.json' }
if (-not $Exe)    { $Exe    = Join-Path $here 'shadowvpn-client.exe' }

# Make paths absolute so they survive the elevated re-launch, which starts in a
# different working directory (system32).
if (-not [System.IO.Path]::IsPathRooted($Config)) { $Config = Join-Path (Get-Location) $Config }
if (-not [System.IO.Path]::IsPathRooted($Exe)) { $Exe = Join-Path (Get-Location) $Exe }

# Re-launch elevated if we are not already Administrator.
$admin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host 'Elevating to Administrator...' -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-Config', "`"$Config`"", '-Exe', "`"$Exe`""
    )
    return
}

if (-not (Test-Path $Exe)) { throw "shadowvpn-client.exe not found: $Exe" }
if (-not (Test-Path $Config)) { throw "config not found: $Config" }
$exeDir = Split-Path -Parent $Exe
if (-not (Test-Path (Join-Path $exeDir 'wintun.dll'))) {
    throw "wintun.dll must sit next to shadowvpn-client.exe (in $exeDir). Download it from https://www.wintun.net/"
}

# Run from the exe's folder so Wintun (wintun.dll) is found at load time.
Set-Location $exeDir
if (-not $env:RUST_LOG) { $env:RUST_LOG = 'info' }

Write-Host "Starting shadowvpn-client  config=$Config" -ForegroundColor Green
Write-Host 'Press Ctrl-C to stop (restores DNS, removes routes, saves cache).' -ForegroundColor Green
& $Exe -c $Config

<#
.SYNOPSIS
    ChainRecon Frida script loader — attach to any app by name, PID, or package.

.DESCRIPTION
    Generalised version of the nooie-specific loadScript.ps1.
    Tries multiple attach strategies:
      1.  frida -U -n <ProcessName> -l <Script>
      2.  frida -U -p <PID>          -l <Script>   (auto-detected from frida-ps)
      3.  frida -U -f <PackageName>  -l <Script>   (spawn mode)

.PARAMETER Script
    Path to the JavaScript file to inject.
.PARAMETER Target
    Process name, PID, or package name (com.example.app).
.PARAMETER Spawn
    Launch the app with frida -f (cold start) instead of attaching.

.EXAMPLE
    .\loadScript.ps1 -Script .\ssl_pinning_bypass.js -Target com.nooie.home
    .\loadScript.ps1 -Script .\list_classes.js -Target com.nooie.home -Spawn
#>
param(
    [Parameter(Mandatory)]
    [string]$Script,

    [Parameter(Mandatory)]
    [string]$Target,

    [switch]$Spawn
)

# --- Validate script path ------------------------------------------------
if (-not (Test-Path $Script)) {
    Write-Host "[!] Script not found: $Script" -ForegroundColor Red
    exit 1
}

# --- Spawn mode -----------------------------------------------------------
if ($Spawn) {
    Write-Host "[*] Spawning $Target with $Script ..." -ForegroundColor Cyan
    frida -U -f $Target -l $Script --no-pause
    exit $LASTEXITCODE
}

# --- Strategy 1: attach by name ------------------------------------------
Write-Host "[*] Trying to attach to '$Target' by name ..." -ForegroundColor Cyan
frida -U -n $Target -l $Script --no-pause 2>$null
if ($LASTEXITCODE -eq 0) { exit 0 }

# --- Strategy 2: find PID via frida-ps -----------------------------------
Write-Host "[*] Name attach failed — searching for PID ..." -ForegroundColor Yellow
$line = frida-ps -U | Select-String -Pattern $Target | Select-Object -First 1
if ($line) {
    $pid = ($line -split '\s+')[0]
    Write-Host "[*] Found PID $pid — attaching ..." -ForegroundColor Cyan
    frida -U -p $pid -l $Script --no-pause
    if ($LASTEXITCODE -eq 0) { exit 0 }
}

# --- Strategy 3: spawn as last resort ------------------------------------
if ($Target -match '\.') {
    Write-Host "[*] Attempting spawn: frida -U -f $Target ..." -ForegroundColor Yellow
    frida -U -f $Target -l $Script --no-pause
    exit $LASTEXITCODE
}

Write-Host "[!] Could not attach to '$Target'." -ForegroundColor Red
exit 1

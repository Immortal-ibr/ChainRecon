param(
    [string[]]$PytestArgs = @("--tb=short", "-q")
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$env:CHAINRECON_LIVE_NMAP = $null
$env:CHAINRECON_LIVE_FRIDA = $null
python -m pytest @PytestArgs

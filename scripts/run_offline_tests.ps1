param(
    [string[]]$PytestArgs = @("--tb=short", "-q")
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$env:CHAINRECON_LIVE_NMAP = $null
$env:CHAINRECON_LIVE_FRIDA = $null
$env:CHAINRECON_LIVE_NOOIE = $null

python -m pytest -m "unit or integration or requirement" @PytestArgs

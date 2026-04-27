param(
    [string]$Target = "192.168.123.99",
    [string]$Interface = "eth0",
    [string]$OutputDir = "nooie_analysis"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$env:CHAINRECON_LIVE_NMAP = "1"
$env:CHAINRECON_LIVE_FRIDA = "1"
$env:CHAINRECON_LIVE_NOOIE = "1"

python -m pytest -m "e2e" --tb=short -q
python chainrecon.py scan $Target --profile iot --interface $Interface --format json --output (Join-Path $OutputDir "live_scan_iot.json")
python chainrecon.py analyze-ssl $Target --ports 443 8443 8883 8080 --format json --output (Join-Path $OutputDir "live_ssl.json")
python chainrecon.py report $OutputDir --format html --output (Join-Path $OutputDir "live_report.html")

param(
    [string]$script
)
$targetProcess = "Nooie"

if (-not $script) {
    Write-Host "Error: missing script"
    exit 1
}

# Try to attach by name first
frida -U -n $targetProcess -l $script
if ($LASTEXITCODE -eq 0) {
    return
}

# Attach with PID
$process = frida-ps -U | findstr $targetProcess | Select-Object -First 1
$fridaPid = $process.Split()[0]

if (-not $fridaPid) {
    Write-Host "Error: process not found"
    exit 1
}

frida -U -p $fridaPid -l $script
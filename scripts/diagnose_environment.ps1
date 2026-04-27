$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

Write-Host "== ChainRecon Environment =="
python --version

Write-Host "`n== Tool Paths =="
Get-Command python,nmap,adb,frida,frida-ps,tshark,jadx,apktool -ErrorAction SilentlyContinue |
    Select-Object Name,Source,Version |
    Format-Table -AutoSize

Write-Host "`n== Nmap Interfaces =="
try { nmap --iflist } catch { Write-Warning $_ }

Write-Host "`n== Windows IPv4 Interfaces =="
try {
    Get-NetIPAddress -AddressFamily IPv4 |
        Select-Object InterfaceAlias,IPAddress,PrefixLength,InterfaceIndex |
        Sort-Object InterfaceAlias |
        Format-Table -AutoSize
} catch { Write-Warning $_ }

Write-Host "`n== ADB Devices =="
try { adb devices } catch { Write-Warning $_ }

Write-Host "`n== Frida Version =="
try { frida --version } catch { Write-Warning $_ }

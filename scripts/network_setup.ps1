#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ChainRecon - Windows Network Setup Script
.DESCRIPTION
    Configures IP forwarding, NAT, and routing for IoT traffic interception
    via a physical router connected over Ethernet.
.PARAMETER EthInterface
    Alias of the Ethernet adapter connected to the IoT router.
.PARAMETER InternetInterface
    Alias of the adapter with active internet (usually Wi-Fi).
.PARAMETER StaticIP
    Static IP address to assign to the Ethernet adapter (e.g. 192.168.123.100).
.PARAMETER SubnetPrefix
    Subnet prefix length (default 24 for /24 = 255.255.255.0).
.PARAMETER NatName
    Name for the NAT configuration (default ChainReconNAT).
.PARAMETER Remove
    If specified, tears down the NAT and removes the static IP.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EthInterface,

    [Parameter(Mandatory = $true)]
    [string]$InternetInterface,

    [Parameter(Mandatory = $false)]
    [string]$StaticIP = "192.168.123.100",

    [Parameter(Mandatory = $false)]
    [int]$SubnetPrefix = 24,

    [Parameter(Mandatory = $false)]
    [string]$NatName = "ChainReconNAT",

    [switch]$Remove
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Step, [string]$Msg)
    Write-Host "[*] Step $Step $Msg" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Msg)
    Write-Host "    [+] $Msg" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Msg)
    Write-Host "    [!] $Msg" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Msg)
    Write-Host "    [!] $Msg" -ForegroundColor Red
}

# --- Teardown mode ---
if ($Remove) {
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  ChainRecon - Removing NAT/Routing" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow

    try {
        $nat = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
        if ($nat) {
            Remove-NetNat -Name $NatName -Confirm:$false
            Write-Ok "Removed NAT '$NatName'"
        } else {
            Write-Warn "NAT '$NatName' not found, nothing to remove"
        }
    } catch {
        Write-Err "Failed to remove NAT: $_"
    }

    try {
        $existing = Get-NetIPAddress -InterfaceAlias $EthInterface -IPAddress $StaticIP -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-NetIPAddress -InterfaceAlias $EthInterface -IPAddress $StaticIP -Confirm:$false
            Write-Ok "Removed static IP $StaticIP from $EthInterface"
        } else {
            Write-Warn "Static IP $StaticIP not found on $EthInterface"
        }
    } catch {
        Write-Err "Failed to remove IP: $_"
    }

    try {
        Set-NetIPInterface -InterfaceAlias $EthInterface -Forwarding Disabled -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceAlias $InternetInterface -Forwarding Disabled -ErrorAction SilentlyContinue
        Write-Ok "IP forwarding disabled on both interfaces"
    } catch {
        Write-Warn "Could not disable forwarding: $_"
    }

    Write-Host "`n[+] Teardown complete." -ForegroundColor Green
    exit 0
}

# --- Setup mode ---
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  ChainRecon - Windows Network Setup" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

# Validate interfaces exist
$ethAdapter = Get-NetAdapter -Name $EthInterface -ErrorAction SilentlyContinue
if (-not $ethAdapter) {
    Write-Err "Ethernet interface '$EthInterface' not found."
    Write-Host "Available adapters:" -ForegroundColor Yellow
    Get-NetAdapter | Format-Table Name, Status, InterfaceDescription -AutoSize
    exit 1
}

$inetAdapter = Get-NetAdapter -Name $InternetInterface -ErrorAction SilentlyContinue
if (-not $inetAdapter) {
    Write-Err "Internet interface '$InternetInterface' not found."
    Write-Host "Available adapters:" -ForegroundColor Yellow
    Get-NetAdapter | Format-Table Name, Status, InterfaceDescription -AutoSize
    exit 1
}

Write-Host "`nConfiguration:" -ForegroundColor Green
Write-Host "  Ethernet (IoT):  $EthInterface ($($ethAdapter.Status))"
Write-Host "  Internet:        $InternetInterface ($($inetAdapter.Status))"
Write-Host "  Static IP:       $StaticIP/$SubnetPrefix"
Write-Host "  NAT Name:        $NatName`n"

# Step 1: Assign static IP (remove any existing addresses first)
Write-Step "1/4:" "Assigning static IP to $EthInterface..."
try {
    # Disable DHCP on the Ethernet adapter so it doesn't fight with static
    Set-NetIPInterface -InterfaceAlias $EthInterface -Dhcp Disabled -ErrorAction SilentlyContinue
    Write-Ok "DHCP disabled on $EthInterface"

    # Remove ALL existing unicast IPv4 addresses on this adapter to avoid conflicts
    $oldIPs = Get-NetIPAddress -InterfaceAlias $EthInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.PrefixOrigin -ne "WellKnown" }
    foreach ($old in $oldIPs) {
        if ($old.IPAddress -ne $StaticIP) {
            Remove-NetIPAddress -InterfaceAlias $EthInterface -IPAddress $old.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
            Write-Ok "Removed old IP $($old.IPAddress) from $EthInterface"
        }
    }

    $existing = Get-NetIPAddress -InterfaceAlias $EthInterface -IPAddress $StaticIP -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Ok "Static IP $StaticIP already assigned to $EthInterface"
    } else {
        New-NetIPAddress -InterfaceAlias $EthInterface -IPAddress $StaticIP -PrefixLength $SubnetPrefix -ErrorAction Stop | Out-Null
        Write-Ok "Assigned $StaticIP/$SubnetPrefix to $EthInterface"
    }
} catch {
    Write-Err "Failed to assign IP: $_"
    exit 1
}

# Step 2: Enable IP forwarding on both interfaces
Write-Step "2/4:" "Enabling IP forwarding..."
try {
    Set-NetIPInterface -InterfaceAlias $EthInterface -Forwarding Enabled
    Set-NetIPInterface -InterfaceAlias $InternetInterface -Forwarding Enabled
    Write-Ok "IP forwarding enabled on $EthInterface and $InternetInterface"
} catch {
    Write-Err "Failed to enable forwarding: $_"
    exit 1
}

# Step 3: Create NAT
Write-Step "3/4:" "Configuring NAT..."
try {
    $existingNat = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
    if ($existingNat) {
        Write-Ok "NAT '$NatName' already exists"
    } else {
        # Compute the network address from static IP and prefix
        $ipBytes = [System.Net.IPAddress]::Parse($StaticIP).GetAddressBytes()
        $maskBytes = [byte[]]::new(4)
        for ($i = 0; $i -lt 32; $i++) {
            if ($i -lt $SubnetPrefix) {
                $maskBytes[[Math]::Floor($i / 8)] = $maskBytes[[Math]::Floor($i / 8)] -bor (128 -shr ($i % 8))
            }
        }
        $netBytes = [byte[]]::new(4)
        for ($i = 0; $i -lt 4; $i++) {
            $netBytes[$i] = $ipBytes[$i] -band $maskBytes[$i]
        }
        $network = ([System.Net.IPAddress]::new($netBytes)).ToString()
        $prefix = "$network/$SubnetPrefix"

        New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $prefix -ErrorAction Stop | Out-Null
        Write-Ok "Created NAT '$NatName' for prefix $prefix"
    }
} catch {
    Write-Err "Failed to configure NAT: $_"
    Write-Warn "You may need to remove an existing NAT first: Get-NetNat | Remove-NetNat"
    exit 1
}

# Step 4: Verify connectivity
Write-Step "4/4:" "Verifying configuration..."
$assignedIP = Get-NetIPAddress -InterfaceAlias $EthInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq $StaticIP }
if ($assignedIP) {
    Write-Ok "IP verified: $($assignedIP.IPAddress)/$($assignedIP.PrefixLength) on $EthInterface"
} else {
    Write-Warn "Could not verify IP assignment"
}

$fwdEth = (Get-NetIPInterface -InterfaceAlias $EthInterface -AddressFamily IPv4).Forwarding
$fwdInet = (Get-NetIPInterface -InterfaceAlias $InternetInterface -AddressFamily IPv4).Forwarding
Write-Ok "Forwarding: $EthInterface=$fwdEth, $InternetInterface=$fwdInet"

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "[+] Network setup complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nYour PC is now acting as a NAT router." -ForegroundColor Cyan
Write-Host "IoT devices should use $StaticIP as their gateway." -ForegroundColor Cyan
Write-Host "Traffic flow: $EthInterface -> $InternetInterface" -ForegroundColor Cyan
Write-Host "`nTo tear down: run with -Remove flag" -ForegroundColor Yellow

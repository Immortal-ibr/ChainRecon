"""Cross-platform network utilities for ChainRecon."""

from __future__ import annotations

import re
import socket
import subprocess
from typing import Dict, List, Optional

from utils.platform_info import is_linux, is_windows


def list_interfaces() -> List[Dict[str, str]]:
    """Return available network interfaces with name and description.

    On Windows, uses tshark -D or PowerShell Get-NetAdapter.
    On Linux, uses ip link or /sys/class/net.
    """
    if is_windows():
        return _list_interfaces_windows()
    return _list_interfaces_linux()


def _list_interfaces_windows() -> List[Dict[str, str]]:
    """Return interfaces with name=friendly_name, device=npf_path, description=friendly_name.

    Tshark -D is the primary source because it lists exactly the devices Npcap
    can open.  The description field in tshark -D output is the Windows adapter
    friendly name ("Ethernet", "Wi-Fi") -- the same name that PowerShell
    New-NetIPAddress / Get-NetAdapter accept.
    """
    from utils.platform_info import find_tool

    tshark = find_tool("tshark")
    if tshark:
        try:
            result = subprocess.run(
                [tshark, "-D"],
                capture_output=True, text=True, timeout=10,
            )
            interfaces = []
            for line in result.stdout.strip().splitlines():
                # Format: "1. \Device\NPF_{GUID} (Description)"
                match = re.match(r"\d+\.\s+(.+?)(?:\s+\((.+)\))?$", line)
                if match:
                    device = match.group(1).strip()
                    friendly = (match.group(2) or device).strip()
                    interfaces.append({
                        "name": friendly,   # human-readable (for UI + PS1 script)
                        "device": device,   # NPF path or adapter name (for tshark -i)
                        "description": friendly,
                    })
            if interfaces:
                return interfaces
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    # Fallback: PowerShell Get-NetAdapter
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10,
        )
        import json
        adapters = json.loads(result.stdout)
        if isinstance(adapters, dict):
            adapters = [adapters]
        return [
            {
                "name": a.get("Name", ""),
                "device": a.get("Name", ""),   # no NPF path without tshark
                "description": f"{a.get('InterfaceDescription', '')} [{a.get('Status', '')}]",
            }
            for a in adapters
        ]
    except Exception:
        return []


def _list_interfaces_linux() -> List[Dict[str, str]]:
    """List interfaces via ip link or /sys/class/net."""
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=10,
        )
        interfaces = []
        for line in result.stdout.strip().splitlines():
            match = re.match(r"\d+:\s+(\S+?):", line)
            if match:
                name = match.group(1)
                state = "UP" if "state UP" in line else "DOWN"
                interfaces.append({"name": name, "description": state})
        return interfaces
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: /sys/class/net
    from pathlib import Path
    net_dir = Path("/sys/class/net")
    if net_dir.exists():
        return [{"name": d.name, "description": ""} for d in net_dir.iterdir() if d.is_dir()]
    return []


def get_default_gateway() -> Optional[str]:
    """Return the default gateway IP address."""
    if is_windows():
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"],
                capture_output=True, text=True, timeout=10,
            )
            gw = result.stdout.strip()
            if gw:
                return gw
        except Exception:
            pass
    else:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=10,
            )
            match = re.search(r"default via (\S+)", result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return None


def get_local_ip() -> Optional[str]:
    """Return the local IP address used for outbound connections."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def enable_ip_forwarding() -> bool:
    """Enable IP forwarding. Returns True on success."""
    if is_windows():
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Set-NetIPInterface -Forwarding Enabled"],
                capture_output=True, timeout=10, check=True,
            )
            return True
        except Exception:
            return False
    else:
        try:
            subprocess.run(
                ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
                capture_output=True, timeout=10, check=True,
            )
            return True
        except Exception:
            return False


def disable_ip_forwarding() -> bool:
    """Disable IP forwarding. Returns True on success."""
    if is_windows():
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Set-NetIPInterface -Forwarding Disabled"],
                capture_output=True, timeout=10, check=True,
            )
            return True
        except Exception:
            return False
    else:
        try:
            subprocess.run(
                ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"],
                capture_output=True, timeout=10, check=True,
            )
            return True
        except Exception:
            return False

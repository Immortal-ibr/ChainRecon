"""Run nmap scans via subprocess and return output file paths."""

from __future__ import annotations

import ipaddress
import json
import platform
import socket
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from runners.base import check_tool, make_output_dir, run_subprocess
from utils.artifacts import artifact_path
from utils.logging_config import get_logger

logger = get_logger("nmap")

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "arp": {
        "label": "ARP Discovery",
        "description": "Host discovery only with ARP on the local subnet",
        "args": ["-sn", "-PR"],
        "suffix": "nmap_arp",
    },
    "quick": {
        "label": "Quick Scan",
        "description": "Top 1000 ports, fast (-T4)",
        "args": ["-Pn", "-sV", "-T4", "--top-ports", "1000"],
        "suffix": "nmap_quick",
    },
    "gentle": {
        "label": "Gentle Scan",
        "description": "Full TCP connect, slow (-T2) -- safe for fragile IoT",
        "args": ["-Pn", "-sT", "-sV", "-T2", "--max-retries", "1", "-r"],
        "suffix": "nmap_gentle",
    },
    "full": {
        "label": "Full Scan",
        "description": "All 65535 ports with OS/version detection (-A)",
        "args": ["-Pn", "-A", "-p-", "-T4", "--version-intensity", "9"],
        "suffix": "nmap_full",
        "timeout": 7200,
    },
    "iot": {
        "label": "IoT Protocol Scan",
        "description": "TCP + UDP for IoT ports (UPnP, mDNS, CoAP, MQTT)",
        "tcp_args": ["-Pn", "-sV", "-T4", "-p", "80,443,8080,8443,8008,1883,8883,502,102,47808"],
        "udp_args": ["-Pn", "-sU", "-T4", "-p", "53,67,123,1900,5353,5683"],
        "suffix": "nmap_iot",
    },
    "vuln": {
        "label": "Vulnerability Scan",
        "description": "NSE vuln scripts + version detection",
        "args": ["-Pn", "-sV", "--script", "vuln", "-T4"],
        "suffix": "nmap_vuln",
        "timeout": 3600,
    },
    "ssl": {
        "label": "SSL / Cert Scan",
        "description": "ssl-cert + ssl-enum-ciphers on HTTPS/MQTT-TLS ports",
        "args": ["-Pn", "--script", "ssl-cert,ssl-enum-ciphers", "-p", "443,8443,8883,8080", "-T4"],
        "suffix": "nmap_ssl",
    },
}


class NmapRunner:
    """Execute nmap scan profiles and return output file paths."""

    def __init__(self, executor: Optional[Callable] = None, preflight_func: Optional[Callable[[str], Dict[str, Any]]] = None):
        self._executor = executor or run_subprocess
        self._preflight_func = preflight_func or preflight_target

    def list_profiles(self) -> List[Dict[str, str]]:
        return [
            {"key": key, "label": p["label"], "description": p["description"]}
            for key, p in SCAN_PROFILES.items()
        ]

    def run_scan(
        self,
        target: str,
        profile: str,
        output_dir: Optional[str] = None,
        interface: Optional[str] = None,
        allow_interface_mismatch: bool = False,
    ) -> Dict[str, Any]:
        nmap_path = check_tool("nmap")

        if profile not in SCAN_PROFILES:
            raise ValueError(f"Unknown scan profile: {profile}")

        cfg = SCAN_PROFILES[profile]
        out_dir = Path(output_dir) if output_dir else make_output_dir()
        out_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Running nmap '%s' scan against %s", profile, target)

        output_files: List[str] = []
        command_results: List[Dict[str, Any]] = []
        default_timeout = cfg.get("timeout", 900)
        configured_interface = interface or _default_interface()
        preflight = (
            _call_preflight(self._preflight_func, target, configured_interface)
            if self._executor is run_subprocess
            else {"target": target, "skipped": True, "reason": "custom executor"}
        )
        if preflight.get("interface_mismatch") and not allow_interface_mismatch:
            raise NmapInterfaceMismatchError(_interface_mismatch_message(preflight), preflight=preflight)

        if profile == "iot":
            tcp_file = str(artifact_path(out_dir, f"{cfg['suffix']}_tcp", ".txt"))
            udp_file = str(artifact_path(out_dir, f"{cfg['suffix']}_udp", ".txt"))
            tcp_xml_file = str(artifact_path(out_dir, f"{cfg['suffix']}_tcp", ".xml"))
            udp_xml_file = str(artifact_path(out_dir, f"{cfg['suffix']}_udp", ".xml"))
            tcp_cmd = [nmap_path] + _inject_interface(cfg["tcp_args"], configured_interface) + [target, "-oN", tcp_file, "-oX", tcp_xml_file]
            udp_cmd = [nmap_path] + _inject_interface(cfg["udp_args"], configured_interface) + [target, "-oN", udp_file, "-oX", udp_xml_file]
            command_results.append(_command_record(tcp_cmd, self._executor(tcp_cmd, timeout=default_timeout)))
            command_results.append(_command_record(udp_cmd, self._executor(udp_cmd, timeout=default_timeout)))
            output_files = [tcp_file, tcp_xml_file, udp_file, udp_xml_file]
        else:
            out_file = str(artifact_path(out_dir, cfg["suffix"], ".txt"))
            xml_file = str(artifact_path(out_dir, cfg["suffix"], ".xml"))
            cmd = [nmap_path] + _inject_interface(cfg["args"], configured_interface) + [target, "-oN", out_file, "-oX", xml_file]
            command_results.append(_command_record(cmd, self._executor(cmd, timeout=default_timeout)))
            output_files = [out_file, xml_file]

        return {
            "profile": profile,
            "backend": "nmap",
            "target": target,
            "interface": configured_interface,
            "nmap_path": nmap_path,
            "preflight": preflight,
            "host_discovery": {
                "pn_assumes_host_up": _profile_uses_pn(cfg),
                "note": "-Pn tells nmap to scan even if host discovery is inconclusive.",
            },
            "commands": command_results,
            "output_files": output_files,
            "output_dir": str(out_dir),
        }


class NmapInterfaceMismatchError(RuntimeError):
    """Raised when an explicit nmap interface cannot route to the target."""

    def __init__(self, message: str, preflight: Dict[str, Any]):
        super().__init__(message)
        self.preflight = preflight


def _profile_uses_pn(cfg: Dict[str, Any]) -> bool:
    arg_sets = [cfg.get("args", []), cfg.get("tcp_args", []), cfg.get("udp_args", [])]
    return any("-Pn" in args for args in arg_sets)


def _call_preflight(func: Callable, target: str, selected_interface: Optional[str]) -> Dict[str, Any]:
    try:
        return func(target, selected_interface=selected_interface)
    except TypeError:
        return func(target)


def _default_interface() -> Optional[str]:
    try:
        from utils.config import get_scan_config
        from utils.network import resolve_scan_interface

        scan_cfg = get_scan_config()
        configured = scan_cfg.get("interface_name") or scan_cfg.get("interface")
        resolved = resolve_scan_interface(str(configured)) if configured else None
        if resolved:
            return resolved.get("runtime_id") or None
        return None
    except Exception:
        return None


def _inject_interface(args: List[str], interface: Optional[str]) -> List[str]:
    if not interface:
        return list(args)
    if "-e" in args:
        return list(args)
    return ["-e", interface, *args]


def _command_record(cmd: List[str], result: Any) -> Dict[str, Any]:
    return {
        "command": [str(part) for part in cmd],
        "powershell_command": powershell_command(cmd),
        "returncode": getattr(result, "returncode", None),
        "stdout_preview": (getattr(result, "stdout", "") or "")[:2000],
        "stderr_preview": (getattr(result, "stderr", "") or "")[:2000],
    }


def powershell_command(cmd: List[str]) -> str:
    """Return a copyable PowerShell command for a subprocess argv list."""
    rendered = []
    for index, part in enumerate(str(item) for item in cmd):
        escaped = part.replace("'", "''")
        if index == 0:
            rendered.append(f"& '{escaped}'")
        elif any(ch.isspace() for ch in part) or part == "":
            rendered.append(f"'{escaped}'")
        else:
            rendered.append(part)
    return " ".join(rendered)


def preflight_target(target: str, timeout: float = 1.0, selected_interface: Optional[str] = None) -> Dict[str, Any]:
    """Collect lightweight reachability context before an nmap scan."""
    cleaned = target.strip().strip('"\'')
    info: Dict[str, Any] = {
        "target": cleaned,
        "target_type": "host",
        "dns_resolved": False,
        "resolved_addresses": [],
        "icmp_echo": None,
        "tcp_probe": [],
        "source_interface": None,
        "selected_interface": _describe_selected_interface(selected_interface),
        "route_interface": None,
        "target_in_selected_subnet": None,
        "interface_mismatch": False,
        "recommended_interface": None,
    }
    if not cleaned:
        info["error"] = "empty target"
        return info
    if "/" in cleaned:
        info["target_type"] = "cidr"
        _annotate_interface_context(info, None, selected_interface)
        info["note"] = "Preflight host probes are skipped for CIDR targets."
        return info
    if "-" in cleaned.rsplit(".", 1)[-1]:
        info["target_type"] = "range"
        _annotate_interface_context(info, None, selected_interface)
        info["note"] = "Preflight host probes are skipped for IP range targets."
        return info

    host = cleaned
    try:
        ipaddress.ip_address(host)
        info["resolved_addresses"] = [host]
        info["dns_resolved"] = True
    except ValueError:
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
            info["resolved_addresses"] = addresses
            info["dns_resolved"] = bool(addresses)
        except socket.gaierror as exc:
            info["dns_error"] = str(exc)

    if info["dns_resolved"]:
        first_ip = next((addr for addr in info["resolved_addresses"] if "." in str(addr)), None)
        _annotate_interface_context(info, first_ip, selected_interface)
        info["icmp_echo"] = _ping_once(host)
        for port in (80, 443, 8080, 8443):
            info["tcp_probe"].append(_tcp_probe(host, port, timeout=timeout))
    return info


def _annotate_interface_context(info: Dict[str, Any], target_ip: Optional[str], selected_interface: Optional[str]) -> None:
    if not selected_interface:
        return
    selected = _describe_selected_interface(selected_interface)
    route = _route_for_target(target_ip) if target_ip else None
    selected_networks = _selected_interface_networks(selected)
    in_selected_subnet = _target_in_networks(target_ip, selected_networks) if target_ip else None
    info["selected_interface"] = selected
    info["route_interface"] = route
    info["target_in_selected_subnet"] = in_selected_subnet
    if route:
        route_name = str(route.get("name") or route.get("runtime_id") or "")
        selected_tokens = {
            str(selected.get("name") or ""),
            str(selected.get("runtime_id") or ""),
            str(selected.get("device") or ""),
        }
        route_tokens = {
            route_name,
            str(route.get("runtime_id") or ""),
            str(route.get("device") or ""),
        }
        if selected_tokens.isdisjoint(route_tokens):
            info["interface_mismatch"] = True
            info["recommended_interface"] = route
    elif in_selected_subnet is False:
        info["interface_mismatch"] = True
        info["recommended_interface"] = None


def _describe_selected_interface(selection: Optional[str]) -> Dict[str, Any] | None:
    if not selection:
        return None
    try:
        from utils.network import resolve_scan_interface

        resolved = resolve_scan_interface(str(selection))
        if resolved:
            return dict(resolved)
    except Exception:
        pass
    return {"runtime_id": str(selection), "name": str(selection), "label": str(selection)}


def _route_for_target(target_ip: Optional[str]) -> Dict[str, Any] | None:
    if not target_ip:
        return None
    if platform.system() == "Windows":
        try:
            ps = (
                "Find-NetRoute -RemoteIPAddress '" + target_ip.replace("'", "''") + "' | "
                "Select-Object -First 1 InterfaceAlias,InterfaceIndex,IPAddress,NextHop,RouteMetric | ConvertTo-Json -Depth 3"
            )
            result = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=10)
            if result.returncode != 0 or not (result.stdout or "").strip():
                return None
            payload = json.loads(result.stdout)
            alias = str(payload.get("InterfaceAlias") or "")
            route = {
                "name": alias,
                "interface_index": payload.get("InterfaceIndex"),
                "source_ip": payload.get("IPAddress"),
                "next_hop": payload.get("NextHop"),
                "route_metric": payload.get("RouteMetric"),
            }
            try:
                from utils.network import resolve_scan_interface

                resolved = resolve_scan_interface(alias)
                if resolved:
                    route.update(resolved)
            except Exception:
                pass
            return route
        except Exception:
            return None
    try:
        result = subprocess.run(["ip", "route", "get", target_ip], capture_output=True, text=True, timeout=5)
        match = None
        if result.returncode == 0:
            import re

            match = re.search(r"\bdev\s+(\S+)", result.stdout or "")
        if match:
            name = match.group(1)
            return {"name": name, "runtime_id": name}
    except Exception:
        return None
    return None


def _selected_interface_networks(selected: Dict[str, Any] | None) -> List[ipaddress.IPv4Network]:
    if not selected:
        return []
    name = str(selected.get("name") or "")
    runtime_id = str(selected.get("runtime_id") or "")
    networks: List[ipaddress.IPv4Network] = []
    if platform.system() == "Windows":
        try:
            ps = "Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Depth 3"
            result = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=10)
            rows = json.loads(result.stdout or "[]")
            if isinstance(rows, dict):
                rows = [rows]
            for row in rows:
                alias = str(row.get("InterfaceAlias") or "")
                if alias not in {name, runtime_id}:
                    continue
                try:
                    networks.append(ipaddress.ip_network(f"{row.get('IPAddress')}/{row.get('PrefixLength')}", strict=False))
                except ValueError:
                    continue
        except Exception:
            return []
    return networks


def _target_in_networks(target_ip: Optional[str], networks: List[ipaddress.IPv4Network]) -> bool | None:
    if not target_ip or not networks:
        return None
    try:
        ip = ipaddress.ip_address(target_ip)
    except ValueError:
        return None
    return any(ip in network for network in networks)


def _interface_mismatch_message(preflight: Dict[str, Any]) -> str:
    selected = preflight.get("selected_interface") or {}
    route = preflight.get("route_interface") or {}
    selected_label = selected.get("label") or selected.get("name") or selected.get("runtime_id") or "selected interface"
    route_label = route.get("label") or route.get("name") or route.get("runtime_id") or "the OS route"
    return (
        f"Selected scan interface '{selected_label}' does not match the route to {preflight.get('target')}. "
        f"The OS would route this target via '{route_label}'. Use the recommended interface or pass "
        "--allow-interface-mismatch if you intentionally want this nmap -e override."
    )


def _ping_once(host: str) -> bool | None:
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", "1000", host]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        return result.returncode == 0
    except Exception:
        return None


def _tcp_probe(host: str, port: int, timeout: float) -> Dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"port": port, "reachable": True}
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"port": port, "reachable": False, "error": str(exc)}

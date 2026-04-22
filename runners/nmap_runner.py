"""Run nmap scans via subprocess and return output file paths."""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from runners.base import check_tool, make_output_dir, run_subprocess
from utils.logging_config import get_logger

logger = get_logger("nmap")

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
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
        preflight = (
            self._preflight_func(target)
            if self._executor is run_subprocess
            else {"target": target, "skipped": True, "reason": "custom executor"}
        )

        if profile == "iot":
            tcp_file = str(out_dir / f"{cfg['suffix']}_tcp.txt")
            udp_file = str(out_dir / f"{cfg['suffix']}_udp.txt")
            tcp_cmd = [nmap_path] + cfg["tcp_args"] + [target, "-oN", tcp_file]
            udp_cmd = [nmap_path] + cfg["udp_args"] + [target, "-oN", udp_file]
            command_results.append(_command_record(tcp_cmd, self._executor(tcp_cmd, timeout=default_timeout)))
            command_results.append(_command_record(udp_cmd, self._executor(udp_cmd, timeout=default_timeout)))
            output_files = [tcp_file, udp_file]
        else:
            out_file = str(out_dir / f"{cfg['suffix']}.txt")
            xml_file = str(out_dir / f"{cfg['suffix']}.xml")
            cmd = [nmap_path] + cfg["args"] + [target, "-oN", out_file, "-oX", xml_file]
            command_results.append(_command_record(cmd, self._executor(cmd, timeout=default_timeout)))
            output_files = [out_file, xml_file]

        return {
            "profile": profile,
            "target": target,
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


def _profile_uses_pn(cfg: Dict[str, Any]) -> bool:
    arg_sets = [cfg.get("args", []), cfg.get("tcp_args", []), cfg.get("udp_args", [])]
    return any("-Pn" in args for args in arg_sets)


def _command_record(cmd: List[str], result: Any) -> Dict[str, Any]:
    return {
        "command": [str(part) for part in cmd],
        "returncode": getattr(result, "returncode", None),
        "stdout_preview": (getattr(result, "stdout", "") or "")[:2000],
        "stderr_preview": (getattr(result, "stderr", "") or "")[:2000],
    }


def preflight_target(target: str, timeout: float = 1.0) -> Dict[str, Any]:
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
    }
    if not cleaned:
        info["error"] = "empty target"
        return info
    if "/" in cleaned:
        info["target_type"] = "cidr"
        info["note"] = "Preflight host probes are skipped for CIDR targets."
        return info
    if "-" in cleaned.rsplit(".", 1)[-1]:
        info["target_type"] = "range"
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
        info["icmp_echo"] = _ping_once(host)
        for port in (80, 443, 8080, 8443):
            info["tcp_probe"].append(_tcp_probe(host, port, timeout=timeout))
    return info


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

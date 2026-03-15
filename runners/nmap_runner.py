"""Run nmap scans via subprocess and return output file paths."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from runners.base import check_tool, make_output_dir, run_subprocess

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
    },
}


class NmapRunner:
    """Execute nmap scan profiles and return output file paths."""

    def __init__(self, executor: Optional[Callable] = None):
        self._executor = executor or run_subprocess

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
        check_tool("nmap")

        if profile not in SCAN_PROFILES:
            raise ValueError(f"Unknown scan profile: {profile}")

        cfg = SCAN_PROFILES[profile]
        out_dir = Path(output_dir) if output_dir else make_output_dir()
        out_dir.mkdir(parents=True, exist_ok=True)

        output_files: List[str] = []

        if profile == "iot":
            tcp_file = str(out_dir / f"{cfg['suffix']}_tcp.txt")
            udp_file = str(out_dir / f"{cfg['suffix']}_udp.txt")
            self._executor(
                ["nmap"] + cfg["tcp_args"] + [target, "-oN", tcp_file],
                timeout=600,
            )
            self._executor(
                ["nmap"] + cfg["udp_args"] + [target, "-oN", udp_file],
                timeout=600,
            )
            output_files = [tcp_file, udp_file]
        else:
            out_file = str(out_dir / f"{cfg['suffix']}.txt")
            self._executor(
                ["nmap"] + cfg["args"] + [target, "-oN", out_file],
                timeout=900,
            )
            output_files = [out_file]

        return {
            "profile": profile,
            "target": target,
            "output_files": output_files,
            "output_dir": str(out_dir),
        }

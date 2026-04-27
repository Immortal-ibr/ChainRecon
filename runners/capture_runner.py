"""Run tcpdump/tshark captures via subprocess and return pcap file paths."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from runners.base import ToolNotFoundError, check_tool, make_output_dir, run_subprocess
from utils.artifacts import artifact_path
from utils.logging_config import get_logger
from utils.platform_info import is_windows

logger = get_logger("capture")

CAPTURE_MODES: Dict[str, Dict[str, str]] = {
    "full": {"label": "Full Capture", "tool": "tshark", "description": "All traffic -- save everything to pcap"},
    "dns": {"label": "DNS Only", "tool": "tshark", "description": "BPF: port 53 -- domain lookups"},
    "http": {"label": "HTTP Only", "tool": "tshark", "description": "BPF: port 80/8080 -- unencrypted API calls"},
    "tls": {"label": "TLS/HTTPS Only", "tool": "tshark", "description": "BPF: port 443/8443 -- encrypted sessions"},
    "iot": {"label": "IoT Ports", "tool": "tshark", "description": "BPF: MQTT 1883/8883, mDNS 5353, UPnP 1900, CoAP 5683"},
    # legacy aliases kept for backward compat
    "basic": {"label": "Basic Capture", "tool": "tshark", "description": "All traffic (alias for full)"},
    "live": {"label": "Live Analysis", "tool": "tshark", "description": "tshark with real-time display"},
    "protocol_stats": {"label": "Protocol Stats", "tool": "tshark", "description": "Capture for protocol breakdown"},
}

# BPF filters applied per mode (combined with target_ip filter when provided)
_MODE_BPF: Dict[str, str] = {
    "dns": "port 53",
    "http": "port 80 or port 8080",
    "tls": "port 443 or port 8443",
    "iot": "port 1883 or port 8883 or port 5353 or port 1900 or port 5683",
}


class CaptureRunner:
    """Execute traffic capture sessions and return pcap file paths."""

    def __init__(self, executor: Optional[Callable] = None):
        self._executor = executor or run_subprocess

    def list_modes(self) -> List[Dict[str, str]]:
        return [
            {"key": key, "label": m["label"], "description": m["description"]}
            for key, m in CAPTURE_MODES.items()
        ]

    def run_capture(
        self,
        interface: str,
        mode: str,
        duration: int = 60,
        target_ip: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        if mode not in CAPTURE_MODES:
            raise ValueError(f"Unknown capture mode: {mode}")

        # Resolve tool to its full path -- try tshark first (preferred on all platforms),
        # fall back to tcpdump on Linux/Mac only.
        tool_path: Optional[str] = None
        tool_name: str = "tshark"
        candidates = ["tshark"] if is_windows() else ["tshark", "tcpdump"]
        for candidate in candidates:
            try:
                tool_path = check_tool(candidate)
                tool_name = candidate
                break
            except ToolNotFoundError:
                continue
        if tool_path is None:
            raise ToolNotFoundError(
                "tshark not found. Install Wireshark from https://www.wireshark.org/ -- "
                "tshark is included and required for packet capture."
            )

        out_dir = Path(output_dir) if output_dir else make_output_dir()
        out_dir.mkdir(parents=True, exist_ok=True)

        # Build BPF filter: combine mode-specific filter with optional target IP
        mode_bpf = _MODE_BPF.get(mode)
        if target_ip and mode_bpf:
            bpf_filter = f"host {target_ip} and ({mode_bpf})"
        elif target_ip:
            bpf_filter = f"host {target_ip}"
        else:
            bpf_filter = mode_bpf

        logger.info("Starting %s capture (mode=%s, iface=%s, duration=%ds)", tool_name, mode, interface, duration)

        if tool_name == "tshark":
            return self._capture_tshark(tool_path, interface, duration, bpf_filter, out_dir, mode)
        return self._capture_tcpdump(tool_path, interface, duration, bpf_filter, out_dir, mode)

    def _capture_tcpdump(self, tool_path: str, interface, duration, bpf_filter, out_dir, mode):
        pcap = str(artifact_path(out_dir, f"capture_{mode}", ".pcap"))
        cmd = [tool_path, "-i", interface, "-s", "0", "-G", str(duration), "-W", "1", "-w", pcap]
        if bpf_filter:
            cmd.append(bpf_filter)  # BPF filter is trailing positional arg for tcpdump
        self._executor(cmd, timeout=duration + 30)
        return {"pcap_files": [pcap], "output_dir": str(out_dir), "mode": mode, "stdout": ""}

    def _capture_tshark(self, tool_path: str, interface, duration, bpf_filter, out_dir, mode):
        pcap = str(artifact_path(out_dir, f"capture_{mode}", ".pcap"))
        cmd = [tool_path, "-i", interface, "-a", f"duration:{duration}", "-w", pcap]
        if bpf_filter:
            cmd.extend(["-f", bpf_filter])
        self._executor(cmd, timeout=duration + 30)
        return {"pcap_files": [pcap], "output_dir": str(out_dir), "mode": mode, "stdout": ""}

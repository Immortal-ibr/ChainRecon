"""Run tcpdump/tshark captures via subprocess and return pcap file paths."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from runners.base import ToolNotFoundError, check_tool, make_output_dir, run_subprocess

CAPTURE_MODES: Dict[str, Dict[str, str]] = {
    "basic": {"label": "Basic Capture", "tool": "tcpdump", "description": "Save raw packets to pcap (for Wireshark)"},
    "live": {"label": "Live Analysis", "tool": "tshark", "description": "tshark with real-time display"},
    "dns": {"label": "DNS Extraction", "tool": "tcpdump", "description": "Capture traffic for DNS analysis"},
    "http": {"label": "HTTP Analysis", "tool": "tcpdump", "description": "Capture traffic for HTTP analysis"},
    "protocol_stats": {"label": "Protocol Stats", "tool": "tcpdump", "description": "Capture traffic for protocol breakdown"},
    "full": {"label": "Full Analysis", "tool": "tcpdump", "description": "Comprehensive capture + full analysis"},
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

        cfg = CAPTURE_MODES[mode]
        tool = cfg["tool"]

        # Fallback: tshark → tcpdump (matches Recon script.sh:460-464)
        try:
            check_tool(tool)
        except ToolNotFoundError:
            if tool == "tshark":
                check_tool("tcpdump")
                tool = "tcpdump"
            else:
                raise

        out_dir = Path(output_dir) if output_dir else make_output_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        bpf_filter = f"host {target_ip}" if target_ip else None

        if mode == "live" and tool == "tshark":
            return self._capture_tshark(interface, duration, bpf_filter, out_dir, timestamp)
        return self._capture_tcpdump(interface, duration, bpf_filter, out_dir, timestamp, mode)

    def _capture_tcpdump(self, interface, duration, bpf_filter, out_dir, ts, mode):
        pcap = str(out_dir / f"traffic_{mode}_{ts}.pcap")
        cmd = ["tcpdump", "-i", interface, "-s", "0", "-G", str(duration), "-W", "1", "-w", pcap]
        if bpf_filter:
            cmd.extend(bpf_filter.split())
        self._executor(cmd, timeout=duration + 30)
        return {"pcap_files": [pcap], "output_dir": str(out_dir), "mode": mode}

    def _capture_tshark(self, interface, duration, bpf_filter, out_dir, ts):
        pcap = str(out_dir / f"traffic_live_{ts}.pcap")
        cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", pcap]
        if bpf_filter:
            cmd.extend(["-f", bpf_filter])
        self._executor(cmd, timeout=duration + 30)
        return {"pcap_files": [pcap], "output_dir": str(out_dir), "mode": "live"}

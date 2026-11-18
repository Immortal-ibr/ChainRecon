"""State for one managed Frida instrumentation session."""

from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class FridaSession:
    session_id: str
    serial: str
    target: str
    attach_target: str
    attach_flag: str
    script_key: str
    parameters: Dict[str, Any]
    command: List[str]
    process: Optional[subprocess.Popen[str]]
    log_path: Path
    summary_path: Path
    rendered_script_path: Path
    start_time: float
    mode: str
    target_running_before: bool
    launch_performed: bool
    frida_server_started: bool
    frida_server_path: Optional[str]
    api_device: Any = None
    api_session: Any = None
    api_script: Any = None
    session_backend: str = "cli"
    health_checks: Dict[str, Any] = field(default_factory=dict)
    summary_written: threading.Event = field(default_factory=threading.Event)
    stop_event: threading.Event = field(default_factory=threading.Event)
    output_line_count: int = 0
    error_line_count: int = 0
    exit_code: Optional[int] = None
    stop_requested: bool = False
    status_reason: str = ""
    reattach_count: int = 0
    events_by_tag: Dict[str, int] = field(default_factory=dict)
    dropped_event_count: int = 0
    target_alive_at_exit: Optional[bool] = None
    reader_threads: List[threading.Thread] = field(default_factory=list)
    watcher_thread: Optional[threading.Thread] = None

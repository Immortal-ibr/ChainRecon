"""Case adapters for the existing offline analyzers."""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Literal, cast

from chainrecon.analysis_catalog import ANALYZER_KINDS, analyzer_for_kind
from chainrecon.case_model import Case, Finding, Observation, RunRecord, RunStatus
from chainrecon.frida_events import parse_event_line
from chainrecon.version import VERSION
from chainrecon.utils.redaction import redact_report_data

_MAX_FRIDA_LOG_LINES = 100_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _observation_summary(analyzer: str, key: str, item: Any, index: int) -> str:
    """Name an observed fact from safe, useful fields in the normalized result."""
    fallback = f"{key} item {index + 1}"
    if not isinstance(item, dict):
        return f"External IP {item}" if key == "external_ips" else fallback
    if analyzer == "scan" and key == "hosts":
        return (f"Host {item.get('ip') or 'unknown address'} ({item.get('host_state') or 'unknown state'}), "
                f"{len(item.get('services') or [])} reported open services")
    if analyzer == "scan" and key in {"service_review_hints", "iot_services", "ambiguous_udp_ports"}:
        return f"{item.get('service') or item.get('protocol') or 'Service'} on port {item.get('port') or 'unknown'}"
    if analyzer == "traffic" and key == "http_requests":
        return f"HTTP {item.get('method') or 'request'} to {item.get('host') or 'unknown host'}"
    if analyzer == "traffic" and key == "dns_queries":
        return f"DNS query {item.get('query') or 'unknown name'}"
    if analyzer == "traffic" and key == "tls_sni":
        return f"TLS SNI {item.get('server_name') or 'unknown name'}"
    if analyzer == "apk" and key == "components":
        return f"{item.get('type') or 'Component'} {item.get('name') or 'unnamed'}"
    if analyzer == "apk" and key == "permissions":
        return f"Permission {item.get('permission') or 'unnamed'}"
    for field in ("title", "name"):
        value = item.get(field)
        if isinstance(value, (str, int)) and value:
            return str(value)[:160]
    for field in ("tag", "ip", "query", "server_name", "address", "path", "service"):
        value = item.get(field)
        if isinstance(value, (str, int)) and value:
            return f"{key}: {value}"[:160]
    return fallback


class CaseAnalysisService:
    """Run one offline analyzer and normalize its output into reviewable records."""

    ANALYZERS = set(ANALYZER_KINDS) - {"firmware"}

    def __init__(self, case: Case):
        self.case = case

    def run(self, evidence_id: str, analyzer: str) -> RunRecord:
        if analyzer not in self.ANALYZERS:
            raise ValueError(f"Unsupported case analyzer: {analyzer}")
        kind = self.case.evidence(evidence_id).kind
        if kind not in ANALYZER_KINDS[analyzer]:
            raise ValueError(f"{analyzer} analysis does not accept {kind} evidence")
        source = self.case.evidence_path(evidence_id)
        started = _now()
        run_id = f"run-{uuid.uuid4().hex}"
        run_root = self.case.root / "runs" / run_id
        run_root.mkdir(parents=True)
        warnings: list[str] = []
        status = "complete"
        result: dict[str, Any] = {}
        try:
            if analyzer == "scan":
                from chainrecon.analysis.scanner import ScannerAnalyzer
                with source.open("rb") as handle:
                    if b"<nmaprun" not in handle.read(4096):
                        raise ValueError("Nmap XML evidence is required for a case scan analysis")
                result = ScannerAnalyzer().parse_nmap_output(str(source))
            elif analyzer == "traffic":
                from chainrecon.analysis.traffic import TrafficAnalyzer
                result = TrafficAnalyzer().analyze_pcap(str(source))
                if result.get("summary", {}).get("result_truncated"):
                    status = "partial"
                    warnings.append("Traffic result collection reached its bound; inspect the raw capture for omitted observations")
            elif analyzer == "apk":
                from chainrecon.analysis.apk_analyzer import APKAnalyzer
                result = APKAnalyzer().analyze(str(source), output_dir=str(run_root / "jadx"))
                errors = int(result.get("metadata", {}).get("jadx_error_count", 0))
                if errors:
                    status = "partial"
                    warnings.append(f"JADX reported {errors} decode errors; app inspection may be incomplete")
                if result.get("metadata", {}).get("jadx_exit_code") == 1:
                    status = "partial"
                    warnings.append("JADX exited with warnings; inspect its output before relying on this run")
                if result.get("metadata", {}).get("manifest_decoded") is False:
                    status = "partial"
                    warnings.append("AndroidManifest.xml was not decoded; permissions and components are incomplete")
            else:
                events: list[dict[str, str]] = []
                with source.open("r", encoding="utf-8", errors="replace") as handle:
                    for line_number, line in enumerate(handle, 1):
                        if line_number > _MAX_FRIDA_LOG_LINES:
                            warnings.append(f"Frida log capped at {_MAX_FRIDA_LOG_LINES:,} lines")
                            status = "partial"
                            break
                        if line.strip():
                            event = parse_event_line(line, reveal_sensitive=False)
                            events.append({"tag": event["tag"], "message": event["message"], "line": str(line_number)})
                result = {"metadata": {"section": "frida", "source": "imported_log"}, "findings": {"events": events}, "summary": {"event_count": len(events)}, "risk_indicators": []}
        except (OSError, RuntimeError, ValueError) as exc:
            status = "failed"
            warnings.append(f"{type(exc).__name__}: {exc}")
        metadata = result.get("metadata")
        if isinstance(metadata, dict):
            for key in ("source", "apk"):
                if key in metadata:
                    metadata[key] = self.case.evidence(evidence_id).path
            if "decompiled_dir" in metadata:
                metadata["decompiled_dir"] = (run_root / "jadx").relative_to(self.case.root).as_posix()
        result = redact_report_data(result)
        artifact = run_root / "analysis.json"
        artifact.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        observations: list[Observation] = []
        findings: list[Finding] = []
        candidate_findings = result.get("findings")
        raw_findings: dict[str, Any] = candidate_findings if isinstance(candidate_findings, dict) else {}
        for key, value in raw_findings.items():
            if isinstance(value, list):
                for index, item in enumerate(value):
                    summary = _observation_summary(analyzer, key, item, index)
                    observations.append(Observation(
                        f"obs-{uuid.uuid4().hex}", f"{analyzer}.{key}", summary,
                        evidence_id, f"analysis.json:findings.{key}[{index}]", "medium",
                        {"derived_artifact": artifact.relative_to(self.case.root).as_posix()},
                    ))
            elif value:
                observations.append(Observation(
                    f"obs-{uuid.uuid4().hex}", f"{analyzer}.{key}", f"{key} observed",
                    evidence_id, f"analysis.json:findings.{key}", "medium",
                    {"derived_artifact": artifact.relative_to(self.case.root).as_posix()},
                ))
        for index, indicator in enumerate(result.get("risk_indicators") or []):
            if not isinstance(indicator, dict):
                continue
            severity = str(indicator.get("severity", "info")).lower()
            if severity not in {"info", "low", "medium", "high", "critical"}:
                severity = "info"
            indicator_observation = Observation(
                f"obs-{uuid.uuid4().hex}", f"{analyzer}.risk_indicator",
                f"Analyzer risk indicator {index + 1}", evidence_id,
                f"analysis.json:risk_indicators[{index}]", "low",
                {"derived_artifact": artifact.relative_to(self.case.root).as_posix()},
            )
            observations.append(indicator_observation)
            findings.append(Finding(
                f"finding-{uuid.uuid4().hex}", str(indicator.get("title") or "Risk indicator"),
                cast(Literal["info", "low", "medium", "high", "critical"], severity), "candidate", (indicator_observation.id,),
                "Analyzer indicator; verify the underlying evidence before disclosure.",
            ))
        run = RunRecord(
            id=run_id, analyzer=analyzer, status=cast(RunStatus, status), input_ids=(evidence_id,),
            started_at=started, completed_at=_now(),
            tool_versions={"chainrecon": VERSION, "python": sys.version.split()[0], "analyzer": analyzer},
            warnings=tuple(warnings), coverage={
                "source_processed": status in {"complete", "partial"},
                "result_complete": status == "complete",
                "observation_count": len(observations),
                "observation_locator_scope": "derived_analysis_artifact",
                **{key: result.get("summary", {}).get(key) for key in (
                    "host_up_count", "scanned_port_count", "dns_query_count", "http_request_count",
                    "tls_sni_count", "event_count", "permission_count", "jadx_error_count",
                    "result_truncated",
                ) if key in result.get("summary", {})},
            },
            observations=tuple(observations), findings=tuple(findings),
            artifacts=(artifact.relative_to(self.case.root).as_posix(),),
        )
        self.case.add_run(run)
        return run


    def record_workflow(self, run_id: str, input_ids: tuple[str, ...], result: dict[str, Any], *, started_at: str) -> RunRecord:
        """Attach a workflow execution to a case without trusting its risk labels."""
        state = result.get("summary", {}).get("status", "failed")
        status = {"completed": "complete", "completed_with_errors": "partial", "partial": "partial", "needs_input": "needs_input", "failed": "failed"}.get(state, "failed")
        run_root = self.case.root / "runs" / run_id
        run_root.mkdir(parents=True, exist_ok=True)
        artifact = run_root / "workflow.json"
        artifact.write_text(json.dumps(redact_report_data(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        observations: list[Observation] = []
        findings: list[Finding] = []
        steps = result.get("findings", {}).get("steps", {})
        effective_inputs = tuple(dict.fromkeys((*input_ids, *(step["evidence_id"] for step in steps.values() if step.get("evidence_id")))))
        for step_id, step in steps.items():
            source_id = step.get("evidence_id") or input_ids[0]
            observation = Observation(
                f"obs-{uuid.uuid4().hex}", "workflow.step",
                f"{step_id}: {step.get('status', 'unknown')}", source_id,
                f"workflow.json:findings.steps.{step_id}", "high",
                {"step_id": step_id, "step_type": step.get("type")},
            )
            observations.append(observation)
            for indicator in step.get("risk_indicators", []) or step.get("result", {}).get("risk_indicators", []):
                if not isinstance(indicator, dict):
                    continue
                severity = str(indicator.get("severity", "info")).lower()
                if severity not in {"info", "low", "medium", "high", "critical"}:
                    severity = "info"
                findings.append(Finding(
                    f"finding-{uuid.uuid4().hex}", str(indicator.get("title") or "Workflow indicator"),
                    cast(Literal["info", "low", "medium", "high", "critical"], severity), "candidate", (observation.id,),
                    "Workflow indicator; verify linked evidence and step output before disclosure.",
                ))
        run = RunRecord(
            run_id, "workflow", cast(RunStatus, status), effective_inputs, started_at, _now(),
            tool_versions={"chainrecon": VERSION, "python": sys.version.split()[0], "workflow_engine": "2"},
            settings={"pipeline_sha256": result.get("metadata", {}).get("pipeline_sha256")},
            warnings=tuple(str(step.get("error")) for step in result.get("findings", {}).get("steps", {}).values() if step.get("error")),
            coverage={"steps_defined": result.get("summary", {}).get("step_count", 0), "completed_steps": result.get("summary", {}).get("completed_step_count", 0), "failed_steps": result.get("summary", {}).get("failed_step_count", 0), "skipped_steps": result.get("summary", {}).get("skipped_step_count", 0)},
            observations=tuple(observations), findings=tuple(findings),
            artifacts=(artifact.relative_to(self.case.root).as_posix(),),
        )
        self.case.add_run(run)
        return run


def analyze_evidence(
    case: Case,
    evidence_id: str,
    *,
    analyzer: str | None = None,
    firmware_mode: str = "container",
    progress: Callable[[str], None] | None = None,
) -> RunRecord:
    """Dispatch a case input through its compatible built-in analyzer."""
    kind = case.evidence(evidence_id).kind
    selected = analyzer_for_kind(kind)
    if selected is None:
        raise ValueError(f"No built-in analyzer accepts {kind} evidence")
    if analyzer is not None and analyzer != selected:
        raise ValueError(f"{analyzer} analysis does not accept {kind} evidence; use {selected}")
    if selected == "firmware":
        from chainrecon.firmware_engine import FirmwareEngine

        return FirmwareEngine().analyze(case, evidence_id, mode=firmware_mode, progress=progress)
    return CaseAnalysisService(case).run(evidence_id, selected)

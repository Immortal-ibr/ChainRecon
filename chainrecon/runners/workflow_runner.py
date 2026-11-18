"""YAML-driven workflow runner for ChainRecon."""

from __future__ import annotations

import json
import re
import ast
import hashlib
import math
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

from chainrecon.analysis import CertAnalyzer, EntropyAnalyzer, MQTTAnalyzer, PcapStatsAnalyzer, RTPAnalyzer, SSLAnalyzer, TrafficAnalyzer, WebRTCAnalyzer
from chainrecon.case_model import Case
from chainrecon.firmware_engine import FirmwareEngine
from chainrecon.frida_events import parse_event_line
from chainrecon.runners.frida_runner import FridaRunner
from chainrecon.runners.nmap_runner import NmapRunner
from chainrecon.utils.artifacts import artifact_path, safe_token, timestamped_dir, write_json_artifact
from chainrecon.utils.community_plugins import load_community_plugin
from chainrecon.utils.config import get_output_dir, load_device_profile


_STEP_TYPES = {"scan", "tls_scan", "pcap_analysis", "frida", "firmware", "report", "community", "assert", "review"}
_PATH_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*$")


def _safe_condition(expression: str, values: Dict[str, Any]) -> bool:
    """Evaluate a small data-only condition language; Python execution is forbidden."""
    if len(expression) > 1000:
        raise ValueError("Workflow condition is too long")
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ValueError("Invalid workflow condition syntax") from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > 80:
        raise ValueError("Workflow condition is too complex")
    allowed = (ast.Expression, ast.Constant, ast.Name, ast.Load, ast.Attribute, ast.List, ast.Tuple,
               ast.UnaryOp, ast.Not, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.NotEq,
               ast.In, ast.NotIn, ast.Gt, ast.GtE, ast.Lt, ast.LtE)
    for node in nodes:
        if not isinstance(node, allowed):
            raise ValueError(f"Unsupported workflow condition element: {type(node).__name__}")
        if isinstance(node, ast.Name) and node.id.startswith("_"):
            raise ValueError("Private names are forbidden in conditions")
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise ValueError("Private attributes are forbidden in conditions")
        if isinstance(node, ast.Constant) and not isinstance(node.value, (str, int, float, bool, type(None))):
            raise ValueError("Unsupported workflow condition literal")

    def evaluate(node: ast.AST) -> Any:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool, type(None))):
            return node.value
        if isinstance(node, ast.Name):
            if node.id.startswith("_"):
                raise ValueError("Private names are forbidden in conditions")
            return values.get(node.id)
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                raise ValueError("Private attributes are forbidden in conditions")
            parent = evaluate(node.value)
            return parent.get(node.attr) if isinstance(parent, dict) else None
        if isinstance(node, (ast.List, ast.Tuple)):
            return [evaluate(item) for item in node.elts]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not evaluate(node.operand)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            return all(evaluate(item) for item in node.values)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            return any(evaluate(item) for item in node.values)
        if isinstance(node, ast.Compare):
            left = evaluate(node.left)
            for operator, comparator in zip(node.ops, node.comparators):
                right = evaluate(comparator)
                if isinstance(operator, ast.Eq):
                    matched = left == right
                elif isinstance(operator, ast.NotEq):
                    matched = left != right
                elif isinstance(operator, ast.In):
                    matched = left in right if isinstance(right, (list, tuple, str, dict)) else False
                elif isinstance(operator, ast.NotIn):
                    matched = left not in right if isinstance(right, (list, tuple, str, dict)) else True
                elif isinstance(operator, (ast.Gt, ast.GtE, ast.Lt, ast.LtE)):
                    if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
                        matched = False
                    else:
                        matched = ((left > right) if isinstance(operator, ast.Gt) else
                                   (left >= right) if isinstance(operator, ast.GtE) else
                                   (left < right) if isinstance(operator, ast.Lt) else left <= right)
                else:
                    raise ValueError("Unsupported workflow comparison")
                if not matched:
                    return False
                left = right
            return True
        raise ValueError(f"Unsupported workflow condition element: {type(node).__name__}")

    return bool(evaluate(tree))


class WorkflowRunner:
    """Execute declarative workflow pipelines."""

    def __init__(self, output_root: Optional[str | Path] = None, *, case: Case | None = None):
        self.output_root = Path(output_root) if output_root else None
        self.case = case

    def _record_path(self, path: Path) -> str:
        resolved = path.resolve()
        if self.case is None:
            return str(resolved)
        if not resolved.is_relative_to(self.case.root):
            raise ValueError("Case workflow artifact path leaves the case folder")
        return resolved.relative_to(self.case.root).as_posix()

    def _restore_path(self, path: str) -> Path:
        candidate = Path(path)
        resolved = (self.case.root / candidate if self.case is not None and not candidate.is_absolute() else candidate).resolve()
        if self.case is not None and not resolved.is_relative_to(self.case.root):
            raise ValueError("Case workflow artifact path leaves the case folder")
        return resolved

    def run(
        self,
        pipeline_path: str,
        *,
        target: Optional[str] = None,
        profile: Optional[str] = None,
        device_profile: Optional[str] = None,
        dry_run: bool = False,
        resume_file: Optional[str] = None,
        approved_steps: Optional[Iterable[str]] = None,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        pipeline_file = Path(pipeline_path)
        definition = yaml.safe_load(pipeline_file.read_text(encoding="utf-8", errors="replace"))
        if definition is None:
            definition = {}
        if not isinstance(definition, dict):
            raise ValueError("Workflow pipeline must be a YAML mapping.")
        steps = definition.get("steps", [])
        if not isinstance(steps, list):
            raise ValueError("Workflow pipeline 'steps' must be a list.")
        self._validate_definition(steps)
        pipeline_hash = hashlib.sha256(pipeline_file.read_bytes()).hexdigest()

        loaded_profile = load_device_profile(device_profile) if device_profile else {}
        context = self._build_context(definition, loaded_profile, target=target, profile=profile)
        context.update(self._typed_inputs(definition.get("inputs"), inputs or {}))
        context_hash = hashlib.sha256(json.dumps(context, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        resume_path = self._restore_path(resume_file) if resume_file else None
        previous = json.loads(resume_path.read_text(encoding="utf-8")) if resume_path else None
        if resume_path and not isinstance(previous, dict):
            raise ValueError("Resume file must contain a workflow report")
        if previous:
            metadata = previous.get("metadata")
            if not isinstance(metadata, dict) or metadata.get("pipeline_sha256") != pipeline_hash:
                raise ValueError("Resume file was created from a different pipeline revision")
            if metadata.get("context_sha256") != context_hash:
                raise ValueError("Resume inputs, target, or profile differ from the saved run")
            if dry_run:
                raise ValueError("A saved workflow run cannot be resumed as a dry run")
            assert resume_path is not None
            if (not isinstance(metadata.get("summary_file"), str) or not isinstance(metadata.get("output_dir"), str)
                    or self._restore_path(metadata["summary_file"]) != resume_path
                    or self._restore_path(metadata["output_dir"]) != resume_path.parent):
                raise ValueError("Resume file has inconsistent artifact paths")
            saved_findings = previous.get("findings")
            saved_steps = saved_findings.get("steps") if isinstance(saved_findings, dict) else None
            declared = {str(step.get("id") or f"step_{index}") for index, step in enumerate(steps, 1)}
            if (not isinstance(saved_steps, dict) or not set(saved_steps).issubset(declared)
                    or any(not isinstance(step, dict) or step.get("status") not in {"running", "interrupted", "needs_input", "completed", "partial", "failed", "skipped"} for step in saved_steps.values())):
                raise ValueError("Resume file contains invalid step records")
        run_dir = (self._restore_path(previous["metadata"]["output_dir"]) if previous else
                   timestamped_dir(self.output_root or (Path.cwd() if dry_run else get_output_dir()), f"workflow_{safe_token(str(definition.get('name') or pipeline_file.stem))}_{uuid.uuid4().hex[:8]}"))
        if not dry_run:
            run_dir.mkdir(parents=True, exist_ok=True)

        results: Dict[str, Dict[str, Any]] = dict((previous or {}).get("findings", {}).get("steps", {}))
        summary_path = (resume_path if previous else
                        artifact_path(run_dir, "workflow_summary", ".json") if not dry_run else None)

        def checkpoint(status: str) -> None:
            if summary_path is None:
                return
            write_json_artifact(summary_path, {
                "metadata": {"pipeline_sha256": pipeline_hash, "context_sha256": context_hash, "pipeline": self._record_path(pipeline_file),
                             "output_dir": self._record_path(run_dir), "summary_file": self._record_path(summary_path)},
                "findings": {"steps": results},
                "summary": {"status": status, "step_count": len(results)},
                "risk_indicators": [],
            })

        checkpoint("running")
        approved = set(approved_steps or [])
        workflow_status = "completed"

        for index, raw_step in enumerate(steps, start=1):
            if not isinstance(raw_step, dict):
                continue
            step_id = str(raw_step.get("id") or f"step_{index}")
            if results.get(step_id, {}).get("status") == "completed":
                continue
            rendered = self._render_value(raw_step, self._render_context(context, results))
            when_expr = rendered.get("when")
            if when_expr and not self._evaluate_when(str(when_expr), context, results):
                results[step_id] = {"id": step_id, "type": rendered.get("type"), "status": "skipped", "reason": "when condition evaluated to false"}
                checkpoint("running")
                continue
            if dry_run:
                results[step_id] = {"id": step_id, "type": rendered.get("type"), "status": "planned", "rendered": rendered}
                continue
            if rendered.get("type") == "review" and step_id not in approved:
                results[step_id] = {"id": step_id, "type": "review", "status": "needs_input", "reason": str(rendered.get("prompt") or "Researcher review required")}
                workflow_status = "needs_input"
                checkpoint(workflow_status)
                break
            results[step_id] = {"id": step_id, "type": rendered.get("type"), "status": "running"}
            checkpoint("running")
            try:
                result = self._execute_step(step_id, rendered, run_dir, context, results)
                results[step_id] = self._normalize_step_record(step_id, result)
                checkpoint("running")
                if results[step_id].get("status") == "failed":
                    workflow_status = "failed" if rendered.get("critical", True) else "completed_with_errors"
                    if rendered.get("critical", True):
                        break
                elif results[step_id].get("status") == "needs_input":
                    workflow_status = "needs_input"
                    break
                elif results[step_id].get("status") == "partial":
                    workflow_status = "partial"
                    if rendered.get("critical", True):
                        break
            except KeyboardInterrupt:
                results[step_id] = {"id": step_id, "type": rendered.get("type"), "status": "interrupted"}
                checkpoint("interrupted")
                raise
            except Exception as exc:
                results[step_id] = {"id": step_id, "type": rendered.get("type"), "status": "failed", "error": str(exc)}
                checkpoint("running")
                if rendered.get("critical", True):
                    workflow_status = "failed"
                    break
                workflow_status = "completed_with_errors"

        summary = {
            "step_count": len(results),
            "completed_step_count": sum(1 for item in results.values() if item.get("status") == "completed"),
            "failed_step_count": sum(1 for item in results.values() if item.get("status") == "failed"),
            "skipped_step_count": sum(1 for item in results.values() if item.get("status") == "skipped"),
            "planned_step_count": sum(1 for item in results.values() if item.get("status") == "planned"),
        }
        report: Dict[str, Any] = {
            "metadata": {
                "pipeline": self._record_path(pipeline_file) if self.case is not None else str(pipeline_file.resolve()),
                "pipeline_sha256": pipeline_hash,
                "context_sha256": context_hash,
                "name": definition.get("name") or pipeline_file.stem,
                "output_dir": None if dry_run else self._record_path(run_dir),
                "device_profile": loaded_profile.get("name") if isinstance(loaded_profile, dict) else None,
                "dry_run": dry_run,
            },
            "findings": {"steps": results},
            "summary": {**summary, "status": workflow_status},
            "risk_indicators": [
                {
                    "severity": "high",
                    "title": "Critical workflow step failed",
                    "details": next(item.get("error", "workflow execution failed") for item in results.values() if item.get("status") == "failed"),
                }
                for _ in ([1] if workflow_status == "failed" else [])
            ],
        }
        if not dry_run:
            assert summary_path is not None
            report["metadata"]["summary_file"] = self._record_path(summary_path)
            write_json_artifact(summary_path, report)
        return report

    def _typed_inputs(self, specs: Any, provided: Dict[str, Any]) -> Dict[str, Any]:
        if specs is None:
            if provided:
                raise ValueError("Workflow does not declare inputs")
            return {}
        if not isinstance(specs, dict):
            raise ValueError("Workflow inputs must be a mapping")
        unknown = set(provided) - set(specs)
        if unknown:
            raise ValueError(f"Undeclared workflow input(s): {', '.join(sorted(unknown))}")
        parsed: Dict[str, Any] = {}
        for name, spec in specs.items():
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name) or not isinstance(spec, dict):
                raise ValueError("Workflow input names and specifications must be mappings with safe names")
            kind = spec.get("type", "string")
            if kind not in {"string", "integer", "number", "boolean", "path"}:
                raise ValueError(f"Unsupported workflow input type for {name}: {kind}")
            value = provided.get(name, spec.get("default"))
            if value is None:
                if spec.get("required", False):
                    raise ValueError(f"Required workflow input missing: {name}")
                continue
            try:
                if kind in {"string", "path"}:
                    if not isinstance(value, str):
                        raise ValueError("expected text")
                elif kind == "integer":
                    if isinstance(value, bool) or (isinstance(value, str) and not re.fullmatch(r"[+-]?[0-9]+", value)) or not isinstance(value, (int, str)):
                        raise ValueError("expected integer")
                    value = int(value)
                elif kind == "number":
                    if isinstance(value, bool):
                        raise ValueError("expected number")
                    value = float(value)
                    if not math.isfinite(value):
                        raise ValueError("expected finite number")
                elif kind == "boolean":
                    if isinstance(value, str):
                        if value.lower() not in {"true", "false"}:
                            raise ValueError("expected true or false")
                        value = value.lower() == "true"
                    elif not isinstance(value, bool):
                        raise ValueError("expected boolean")
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid workflow input {name}: {exc}") from exc
            parsed[name] = value
        return parsed

    def _build_context(self, definition: Dict[str, Any], device_profile: Dict[str, Any], *, target: Optional[str], profile: Optional[str]) -> Dict[str, Any]:
        variables = dict(definition.get("variables") or {})
        context: Dict[str, Any] = {"device_profile": device_profile}
        context.update(device_profile if isinstance(device_profile, dict) else {})
        context.update(variables)
        if target:
            context["target"] = target
        if profile:
            context["profile"] = profile
        context.setdefault("target", (device_profile or {}).get("target"))
        context.setdefault(
            "profile",
            (device_profile or {}).get("scan_defaults", {}).get("profile")
            or (device_profile or {}).get("scan", {}).get("profile"),
        )
        context.setdefault(
            "frida_target",
            (device_profile or {}).get("frida_defaults", {}).get("target")
            or (device_profile or {}).get("frida", {}).get("target"),
        )
        return context

    def _validate_definition(self, steps: List[Dict[str, Any]]) -> None:
        declared_ids = [str(step.get("id") or f"step_{index}") for index, step in enumerate(steps, start=1) if isinstance(step, dict)]
        seen: List[str] = []
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                raise ValueError(f"Workflow step {index} must be a mapping.")
            step_id = str(step.get("id") or f"step_{index}")
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", step_id):
                raise ValueError(f"Workflow step ID must use letters, digits, and underscores: {step_id}")
            step_type = str(step.get("type") or "").strip()
            if not step_type:
                raise ValueError(f"Workflow step '{step_id}' is missing a type.")
            if step_type not in _STEP_TYPES:
                raise ValueError(f"Workflow step '{step_id}' has unsupported type: {step_type}")
            if step_id in seen:
                raise ValueError(f"Duplicate workflow step ID: {step_id}")
            when_expr = str(step.get("when") or "")
            if when_expr:
                _safe_condition(when_expr, {})
            if step_type == "assert" and step.get("condition"):
                _safe_condition(str(step["condition"]), {})
            references = re.findall(r"steps\.([A-Za-z0-9_]+)", when_expr)
            unknown = [ref for ref in references if ref not in declared_ids]
            if unknown:
                raise ValueError(f"Workflow step '{step_id}' references unknown step(s) in when: {', '.join(sorted(set(unknown)))}")
            future = [ref for ref in references if ref not in seen]
            if future:
                raise ValueError(f"Workflow step '{step_id}' references step(s) before they execute: {', '.join(sorted(set(future)))}")
            seen.append(step_id)

    def _execute_step(self, step_id: str, step: Dict[str, Any], run_dir: Path, context: Dict[str, Any], results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        step_type = str(step.get("type") or "").strip().lower()
        if not step_type:
            raise ValueError(f"Workflow step '{step_id}' is missing a type.")
        if step_type == "scan":
            return self._step_scan(step_id, step, run_dir)
        if step_type == "tls_scan":
            return self._step_tls_scan(step_id, step, run_dir)
        if step_type == "pcap_analysis":
            return self._step_pcap(step_id, step, run_dir)
        if step_type == "frida":
            return self._step_frida(step_id, step, run_dir)
        if step_type == "firmware":
            return self._step_firmware(step_id, step, run_dir, context)
        if step_type == "report":
            return self._step_report(step_id, step, run_dir, results)
        if step_type == "community":
            return self._step_community(step_id, step, run_dir)
        if step_type == "assert":
            return self._step_assert(step_id, step, context, results)
        if step_type == "review":
            return {"type": "review", "status": "completed", "summary": {"approved": True}}
        raise ValueError(f"Unsupported workflow step type: {step_type}")

    def _normalize_step_record(self, step_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
        record = {"id": step_id, **result}
        payload = result.get("result") if isinstance(result.get("result"), dict) else {}
        if isinstance(payload, dict):
            for key in ("metadata", "findings", "summary", "risk_indicators", "artifacts"):
                if key in payload and key not in record:
                    record[key] = payload[key]
        record.setdefault("summary", {})
        record.setdefault("findings", {})
        return record

    def _step_scan(self, step_id: str, step: Dict[str, Any], run_dir: Path) -> Dict[str, Any]:
        import chainrecon
        from chainrecon.analysis.scanner import ScannerAnalyzer

        target = str(step.get("target") or "").strip()
        if not target:
            raise ValueError("Scan step requires a target.")
        runner = NmapRunner()
        scan_result = runner.run_scan(
            target,
            str(step.get("profile") or "quick"),
            interface=step.get("interface"),
            allow_interface_mismatch=bool(step.get("allow_interface_mismatch", False)),
        )
        analyzer = ScannerAnalyzer()
        output_files = [Path(path) for path in scan_result.get("output_files", []) if Path(path).exists()]
        xml_files = [path for path in output_files if path.suffix.lower() == ".xml"]
        if not xml_files:
            raise RuntimeError("Nmap scan produced no XML evidence; coverage is unknown")
        parsed = [analyzer.parse_nmap_output(str(path)) for path in xml_files]
        result = chainrecon.combine_scan_results(scan_result, parsed)
        summary = result.get("summary")
        if not isinstance(summary, dict):
            summary = {}
            result["summary"] = summary
        summary.setdefault("open_ports", _extract_open_ports(result))
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "scan", "status": "completed", "output_path": self._record_path(output_path), "result": result}

    def _step_tls_scan(self, step_id: str, step: Dict[str, Any], run_dir: Path) -> Dict[str, Any]:
        target = str(step.get("target") or "").strip()
        if not target:
            raise ValueError("TLS scan step requires a target.")
        ports = [int(port) for port in (step.get("ports") or [443, 8443, 8883, 8080])]
        analyzer = SSLAnalyzer()
        certificates = analyzer.probe_certificates(target, ports)
        ciphers = analyzer.analyze_ciphers(target, ports)
        security = analyzer.assess_tls_security(certificates, ciphers)
        result = {
            "metadata": {"target": target, "ports": ports, "section": "ssl"},
            "findings": {
                "certificates": certificates.get("findings", {}).get("certificates", []),
                "cipher_analysis": ciphers.get("findings", {}).get("cipher_analysis", []),
                "security_findings": security.get("findings", {}).get("security_findings", []),
            },
            "summary": {
                "certificate_count": certificates.get("summary", {}).get("certificate_count", 0),
                "reachable_port_count": certificates.get("summary", {}).get("reachable_ports", 0),
                "weak_cipher_count": ciphers.get("summary", {}).get("weak_cipher_count", 0),
                "risk_rating": security.get("summary", {}).get("risk_rating", "low"),
            },
            "risk_indicators": security.get("risk_indicators", []),
        }
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "tls_scan", "status": "completed", "output_path": self._record_path(output_path), "result": result}

    def _step_pcap(self, step_id: str, step: Dict[str, Any], run_dir: Path) -> Dict[str, Any]:
        pcap_path = str(step.get("pcap") or step.get("input") or "").strip()
        if not pcap_path:
            raise ValueError("PCAP analysis step requires a pcap path.")
        analyzer_name = str(step.get("analyzer") or "traffic").lower()
        if analyzer_name == "traffic":
            result = TrafficAnalyzer().analyze_pcap(pcap_path)
        elif analyzer_name == "cert":
            result = CertAnalyzer().analyze_pcap(pcap_path)
        else:
            packets, capture = TrafficAnalyzer()._load_packets(pcap_path)
            try:
                analyzers = {
                    "pcap_stats": PcapStatsAnalyzer,
                    "mqtt": MQTTAnalyzer,
                    "webrtc": WebRTCAnalyzer,
                    "entropy": EntropyAnalyzer,
                    "rtp": RTPAnalyzer,
                }
                if analyzer_name not in analyzers:
                    raise ValueError(f"Unsupported pcap analyzer: {analyzer_name}")
                result = analyzers[analyzer_name]().analyze(packets)
                result.setdefault("metadata", {})["capture_truncated"] = packets.truncated
                result.setdefault("summary", {})["result_truncated"] = packets.truncated
            finally:
                if hasattr(capture, "close"):
                    capture.close()
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "pcap_analysis", "status": "partial" if result.get("summary", {}).get("result_truncated") else "completed", "output_path": self._record_path(output_path), "result": result}

    def _step_frida(self, step_id: str, step: Dict[str, Any], run_dir: Path) -> Dict[str, Any]:
        target = str(step.get("target") or "").strip()
        script = str(step.get("script") or "").strip()
        if not target:
            raise ValueError("Frida step requires a target package or process.")
        if not script:
            raise ValueError("Frida step requires a script key.")
        runner = FridaRunner(validate_device=False)
        parameters = dict(step.get("parameters") or {})
        custom_script_path = step.get("custom_script_path")
        rendered_path = None
        if not custom_script_path and parameters:
            rendered_path = runner.render_script(script, parameters, run_dir)
            custom_script_path = str(rendered_path)
            script_key = ""
        else:
            script_key = script
        if bool(step.get("spawn", False)):
            frida_result = runner.spawn_and_run(target, script_key, custom_script_path=custom_script_path)
        else:
            frida_result = runner.run_script(target, script_key, custom_script_path=custom_script_path)
        lines = [line.strip() for line in str(frida_result.get("stdout") or "").splitlines() if line.strip()]
        events = [parse_event_line(line) for line in lines[:10_000]]
        events_by_tag: Dict[str, int] = {}
        for event in events:
            tag = event["tag"]
            events_by_tag[tag] = events_by_tag.get(tag, 0) + 1
        returncode = int(frida_result.get("returncode", 1))
        session_status = "failed" if returncode else "partial" if len(lines) > 10_000 else "completed"
        result: Dict[str, Any] = {
            "metadata": {"section": "frida", "target": target, "script": script, "rendered_script_path": self._record_path(rendered_path) if rendered_path else custom_script_path},
            "findings": {
                "session": {"target": target, "script": script, "status": session_status},
                "events_by_tag": events_by_tag,
                "events": events,
                "hook_events": [event for event in events if event["tag"] in {"HOOK", "STATUS"}],
                "error_events": [event for event in events if event["tag"] in {"ERROR", "WARN"}],
            },
            "summary": {"status": session_status, "returncode": returncode, "events_recorded": len(events), "events_truncated": max(0, len(lines) - len(events))},
            "risk_indicators": [],
        }
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "frida", "status": result["summary"]["status"], "output_path": self._record_path(output_path), "result": result}

    def _step_firmware(self, step_id: str, step: Dict[str, Any], run_dir: Path, context: Dict[str, Any]) -> Dict[str, Any]:
        if step.get("rules"):
            raise ValueError("Firmware rules are not supported by the evidence-led engine; use a versioned advisory snapshot")
        evidence_id = str(step.get("evidence_id") or "").strip()
        firmware_path = str(step.get("firmware") or step.get("image") or step.get("input") or "").strip()
        if not evidence_id and not firmware_path:
            raise ValueError("Firmware step requires an evidence_id or image path")
        if evidence_id and self.case is None:
            raise ValueError("Firmware evidence_id requires a case-backed workflow")
        case = self.case or Case.create(run_dir / safe_token(step_id) / "case")
        if evidence_id:
            case.evidence_path(evidence_id)
        elif firmware_path:
            evidence_id = case.add_evidence(firmware_path, kind="firmware").id
        run = FirmwareEngine().analyze(case, evidence_id, mode=str(step.get("mode") or "container"), advisory_snapshot=step.get("advisory_snapshot"))
        result = {
            "metadata": {"section": "firmware", "case_path": "." if self.case is not None else str(case.root), "run_id": run.id, "evidence_id": evidence_id},
            "findings": {"candidate_findings": [{"id": finding.id, "title": finding.title, "severity": finding.severity} for finding in run.findings]},
            "summary": {"status": run.status, "observation_count": len(run.observations), "candidate_count": len(run.findings), "coverage": run.coverage, "warnings": list(run.warnings)},
            "risk_indicators": [],
        }
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "firmware", "status": run.status if run.status != "complete" else "completed", "evidence_id": evidence_id, "firmware_run_id": run.id, "output_path": self._record_path(output_path), "result": result}

    def _step_report(self, step_id: str, step: Dict[str, Any], run_dir: Path, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        import chainrecon
        from chainrecon.analysis import ReportGenerator

        inputs = [str(path) for path in (step.get("inputs") or [])]
        if not inputs:
            inputs = [str(item["output_path"]) for item in results.values() if item.get("output_path")]
        merged = chainrecon.load_report_inputs([str(self._restore_path(path)) for path in inputs])
        generator = ReportGenerator()
        for section, payload in merged.items():
            generator.add_results(section, payload, mode="append" if section == "frida" else "replace")
        formats = step.get("formats") or [step.get("format") or "xlsx"]
        outputs = []
        for format_name in formats:
            output_path = run_dir / f"{safe_token(step_id)}.{format_name}"
            generator.generate(str(format_name), str(output_path))
            outputs.append(self._record_path(output_path))
        result = {"metadata": {"section": "report"}, "findings": {"inputs": inputs, "outputs": outputs}, "summary": {"output_count": len(outputs)}, "risk_indicators": []}
        return {"type": "report", "status": "completed", "output_path": outputs[0] if outputs else None, "result": result}

    def _step_community(self, step_id: str, step: Dict[str, Any], run_dir: Path) -> Dict[str, Any]:
        plugin_name = str(step.get("plugin") or "").strip()
        input_path = str(step.get("input") or step.get("path") or "").strip()
        if not plugin_name:
            raise ValueError("Community step requires a plugin name.")
        if step.get("trusted") is not True:
            raise ValueError("Community plugin execution requires trusted: true in the workflow")
        plugin = load_community_plugin(plugin_name, trusted=True)
        result = plugin.analyze(input_path=input_path, output_dir=str(run_dir), step=step)
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "community", "status": "completed", "output_path": self._record_path(output_path), "result": result}

    def _step_assert(self, step_id: str, step: Dict[str, Any], context: Dict[str, Any], results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        condition = str(step.get("condition") or "").strip()
        if not condition:
            raise ValueError(f"Assert step '{step_id}' requires a condition.")
        if not self._evaluate_when(condition, context, results):
            raise AssertionError(str(step.get("message") or f"Assertion failed for workflow step '{step_id}'."))
        result = {
            "metadata": {"section": "workflow_assert", "step_id": step_id},
            "findings": {"condition": condition, "message": step.get("message")},
            "summary": {"assertion_passed": True},
            "risk_indicators": [],
        }
        return {"type": "assert", "status": "completed", "result": result}

    def _render_context(self, context: Dict[str, Any], results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        return {**context, "steps": results}

    def _render_value(self, value: Any, context: Dict[str, Any]) -> Any:
        if isinstance(value, str):
            pattern = re.compile(r"\{\{\s*([^}]+?)\s*\}\}|\$\{\s*([^}]+?)\s*\}")
            def replace(match: re.Match[str]) -> str:
                path = (match.group(1) or match.group(2)).strip()
                if not _PATH_RE.fullmatch(path):
                    raise ValueError(f"Invalid workflow template path: {path}")
                resolved = self._resolve_path(context, path)
                return "" if resolved is None else str(resolved)
            return pattern.sub(replace, value)
        if isinstance(value, list):
            return [self._render_value(item, context) for item in value]
        if isinstance(value, dict):
            return {key: self._render_value(item, context) for key, item in value.items()}
        return value

    def _resolve_path(self, context: Dict[str, Any], path: str) -> Any:
        current: Any = context
        for part in path.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
            if current is None:
                return None
        return current

    def _evaluate_when(self, expr: str, context: Dict[str, Any], results: Dict[str, Dict[str, Any]]) -> bool:
        return _safe_condition(expr, {**context, "steps": results})


def _extract_open_ports(result: Dict[str, Any]) -> List[int]:
    ports: set[int] = set()
    raw_findings = result.get("findings")
    findings = raw_findings if isinstance(raw_findings, dict) else {}
    for host in findings.get("hosts", []) if isinstance(findings.get("hosts"), list) else []:
        if not isinstance(host, dict):
            continue
        for item in [*(host.get("services") or []), *(host.get("ports") or [])]:
            if not isinstance(item, dict):
                continue
            state = str(item.get("state") or "open").lower()
            if state != "open":
                continue
            try:
                value = item.get("port")
                if value is not None:
                    ports.add(int(value))
            except (TypeError, ValueError):
                continue
    return sorted(ports)

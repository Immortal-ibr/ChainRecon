"""YAML-driven workflow runner for ChainRecon."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

from chainrecon.analysis import APKAnalyzer, CertAnalyzer, EntropyAnalyzer, MQTTAnalyzer, PcapStatsAnalyzer, RTPAnalyzer, SSLAnalyzer, TrafficAnalyzer, WebRTCAnalyzer
from chainrecon.analysis.firmware_analyzer import FirmwareAnalyzer
from chainrecon.runners.frida_runner import FridaRunner
from chainrecon.runners.nmap_runner import NmapRunner
from chainrecon.utils.artifacts import artifact_path, safe_token, timestamped_dir, write_json_artifact
from chainrecon.utils.community_plugins import load_community_plugin
from chainrecon.utils.config import get_output_dir, load_device_profile


class _SafeNamespace:
    """Namespace used by workflow expressions; missing attributes resolve empty."""

    def __init__(self, **values: Any) -> None:
        self.__dict__.update(values)

    def __getattr__(self, _name: str) -> Any:
        return _SafeNamespace()

    def __bool__(self) -> bool:
        return False

    def __contains__(self, _item: Any) -> bool:
        return False


class WorkflowRunner:
    """Execute declarative workflow pipelines."""

    def __init__(self, output_root: Optional[str | Path] = None):
        self.output_root = Path(output_root) if output_root else get_output_dir()

    def run(
        self,
        pipeline_path: str,
        *,
        target: Optional[str] = None,
        profile: Optional[str] = None,
        device_profile: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        pipeline_file = Path(pipeline_path)
        definition = yaml.safe_load(pipeline_file.read_text(encoding="utf-8", errors="replace")) or {}
        if not isinstance(definition, dict):
            raise ValueError("Workflow pipeline must be a YAML mapping.")
        steps = definition.get("steps") or []
        if not isinstance(steps, list):
            raise ValueError("Workflow pipeline 'steps' must be a list.")
        self._validate_definition(steps)

        loaded_profile = load_device_profile(device_profile) if device_profile else {}
        context = self._build_context(definition, loaded_profile, target=target, profile=profile)
        run_dir = timestamped_dir(self.output_root, f"workflow_{safe_token(str(definition.get('name') or pipeline_file.stem))}")
        run_dir.mkdir(parents=True, exist_ok=True)

        results: Dict[str, Dict[str, Any]] = {}
        workflow_status = "completed"

        for index, raw_step in enumerate(steps, start=1):
            if not isinstance(raw_step, dict):
                continue
            step_id = str(raw_step.get("id") or f"step_{index}")
            rendered = self._render_value(raw_step, self._render_context(context, results))
            when_expr = rendered.get("when")
            if when_expr and not self._evaluate_when(str(when_expr), context, results):
                results[step_id] = {"id": step_id, "type": rendered.get("type"), "status": "skipped", "reason": "when condition evaluated to false"}
                continue
            if dry_run:
                results[step_id] = {"id": step_id, "type": rendered.get("type"), "status": "planned", "rendered": rendered}
                continue
            try:
                result = self._execute_step(step_id, rendered, run_dir, context, results)
                results[step_id] = self._normalize_step_record(step_id, result)
            except Exception as exc:
                results[step_id] = {"id": step_id, "type": rendered.get("type"), "status": "failed", "error": str(exc)}
                if rendered.get("critical", False):
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
        report = {
            "metadata": {
                "pipeline": str(pipeline_file.resolve()),
                "name": definition.get("name") or pipeline_file.stem,
                "output_dir": str(run_dir.resolve()),
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
        write_json_artifact(artifact_path(run_dir, "workflow_summary", ".json"), report)
        return report

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
            step_type = str(step.get("type") or "").strip()
            if not step_type:
                raise ValueError(f"Workflow step '{step_id}' is missing a type.")
            when_expr = str(step.get("when") or "")
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
        analyzer = __import__("analysis", fromlist=["ScannerAnalyzer"]).ScannerAnalyzer()
        parsed = [
            analyzer.parse_nmap_output(path)
            for path in scan_result.get("output_files", [])
            if Path(path).exists() and Path(path).suffix.lower() == ".txt"
        ]
        result = chainrecon.combine_scan_results(scan_result, parsed) if parsed else {"metadata": scan_result, "findings": {}, "summary": {}, "risk_indicators": []}
        summary = result.setdefault("summary", {})
        summary.setdefault("open_ports", _extract_open_ports(result))
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "scan", "status": "completed", "output_path": str(output_path), "result": result}

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
        return {"type": "tls_scan", "status": "completed", "output_path": str(output_path), "result": result}

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
            finally:
                if hasattr(capture, "close"):
                    capture.close()
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "pcap_analysis", "status": "completed", "output_path": str(output_path), "result": result}

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
        events_by_tag: Dict[str, int] = {}
        for line in lines:
            if line.startswith("[") and "]" in line:
                tag = line[1 : line.index("]")]
                events_by_tag[tag] = events_by_tag.get(tag, 0) + 1
        result = {
            "metadata": {"section": "frida", "target": target, "script": script, "rendered_script_path": str(rendered_path) if rendered_path else custom_script_path},
            "findings": {
                "session": {"target": target, "script": script, "status": "completed" if int(frida_result.get("returncode", 1)) == 0 else "failed"},
                "events_by_tag": events_by_tag,
                "hook_events": [line for line in lines if line.startswith("[HOOK]") or line.startswith("[STATUS]")],
                "error_events": [line for line in lines if line.startswith("[ERROR]") or line.startswith("[WARN]")],
            },
            "summary": {"status": "completed" if int(frida_result.get("returncode", 1)) == 0 else "failed", "returncode": int(frida_result.get("returncode", 1))},
            "risk_indicators": [],
        }
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "frida", "status": "completed", "output_path": str(output_path), "result": result}

    def _step_firmware(self, step_id: str, step: Dict[str, Any], run_dir: Path, context: Dict[str, Any]) -> Dict[str, Any]:
        firmware_path = str(step.get("firmware") or step.get("image") or step.get("input") or "").strip()
        if not firmware_path:
            raise ValueError("Firmware step requires an image path.")
        firmware_dir = run_dir / safe_token(step_id)
        result = FirmwareAnalyzer().analyze(
            firmware_path,
            output_dir=str(firmware_dir),
            rules=dict(step.get("rules") or context.get("firmware_rules") or {}),
        )
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "firmware", "status": "completed", "output_path": str(output_path), "result": result}

    def _step_report(self, step_id: str, step: Dict[str, Any], run_dir: Path, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        import chainrecon
        from chainrecon.analysis import ReportGenerator

        inputs = [str(path) for path in (step.get("inputs") or [])]
        if not inputs:
            inputs = [str(item["output_path"]) for item in results.values() if item.get("output_path")]
        merged = chainrecon.load_report_inputs(inputs)
        generator = ReportGenerator()
        for section, payload in merged.items():
            generator.add_results(section, payload, mode="append" if section == "frida" else "replace")
        formats = step.get("formats") or [step.get("format") or "xlsx"]
        outputs = []
        for format_name in formats:
            output_path = run_dir / f"{safe_token(step_id)}.{format_name}"
            generator.generate(str(format_name), str(output_path))
            outputs.append(str(output_path))
        result = {"metadata": {"section": "report"}, "findings": {"inputs": inputs, "outputs": outputs}, "summary": {"output_count": len(outputs)}, "risk_indicators": []}
        return {"type": "report", "status": "completed", "output_path": outputs[0] if outputs else None, "result": result}

    def _step_community(self, step_id: str, step: Dict[str, Any], run_dir: Path) -> Dict[str, Any]:
        plugin_name = str(step.get("plugin") or "").strip()
        input_path = str(step.get("input") or step.get("path") or "").strip()
        if not plugin_name:
            raise ValueError("Community step requires a plugin name.")
        plugin = load_community_plugin(plugin_name)
        result = plugin.analyze(input_path=input_path, output_dir=str(run_dir), step=step)
        output_path = artifact_path(run_dir, f"workflow_{safe_token(step_id)}", ".json")
        write_json_artifact(output_path, result)
        return {"type": "community", "status": "completed", "output_path": str(output_path), "result": result}

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
            return pattern.sub(lambda match: str(self._resolve_path(context, (match.group(1) or match.group(2)).strip()) or ""), value)
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
                current = getattr(current, part, None)
            if current is None:
                return None
        return current

    def _evaluate_when(self, expr: str, context: Dict[str, Any], results: Dict[str, Dict[str, Any]]) -> bool:
        scope = {key: self._to_namespace(value) for key, value in {**context, "steps": results}.items()}
        return bool(eval(expr, {"__builtins__": {}}, scope))

    def _to_namespace(self, value: Any) -> Any:
        if isinstance(value, dict):
            return _SafeNamespace(**{key: self._to_namespace(item) for key, item in value.items()})
        if isinstance(value, list):
            return [self._to_namespace(item) for item in value]
        return value


def _extract_open_ports(result: Dict[str, Any]) -> List[int]:
    ports: set[int] = set()
    findings = result.get("findings") if isinstance(result.get("findings"), dict) else {}
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
                ports.add(int(item.get("port")))
            except (TypeError, ValueError):
                continue
    return sorted(ports)

"""Aggregate analysis results and render reports."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Optional

from models.finding import FindingCollection
from plugins import get_plugin


class ReportGenerator:
    """Collect analyzer outputs and hand them to a report plugin."""

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {}
        self._findings = FindingCollection()

    # -- Legacy convenience setters (still work) ----------------------

    def add_traffic_results(self, results: Dict[str, Any]) -> None:
        self._data["traffic"] = results

    def add_ssl_results(self, results: Dict[str, Any]) -> None:
        self._data["ssl"] = results

    def add_scan_results(self, results: Dict[str, Any]) -> None:
        self._data["scan"] = results

    # -- Generic setters for any analyzer -----------------------------

    def add_results(self, section: str, results: Dict[str, Any], mode: str = "replace") -> None:
        """Add results from any analyzer under *section* key."""
        if mode == "replace":
            self._data[section] = results
            return
        if mode != "append":
            raise ValueError(f"Unsupported add_results mode: {mode}")
        self._data[section] = _append_section_payload(section, self._data.get(section), results)

    def add_finding(self, finding) -> None:
        """Append a single Finding to the collection."""
        self._findings.add(finding)

    def add_findings(self, findings) -> None:
        """Append an iterable of Findings."""
        for f in findings:
            self._findings.add(f)

    # -- Accessors ----------------------------------------------------

    @property
    def findings(self) -> FindingCollection:
        return self._findings

    def get_data(self) -> Dict[str, Any]:
        data = deepcopy(self._data)
        if self._findings:
            data["findings_summary"] = {
                "total": len(self._findings),
                "by_severity": self._findings.severity_counts,
            }
            data["findings"] = self._findings.to_list()
        return data

    # -- Report generation --------------------------------------------

    def generate(self, format_name: str, output_path: str) -> str:
        return get_plugin(format_name).generate(normalize_report_data(self.get_data()), output_path)


def normalize_report_data(data: Dict[str, Any]) -> Dict[str, Any]:
    normalized = deepcopy(data)
    for section, payload in list(normalized.items()):
        if section in {"findings", "findings_summary"}:
            continue
        if section == "frida":
            normalized[section] = normalize_frida_section(payload)
            continue
        normalized[section] = normalize_report_section(payload, section=section)
    return normalized


def normalize_report_section(payload: Any, *, section: str = "analysis") -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "metadata": {"section": section},
            "summary": {},
            "findings": {"value": payload},
            "risk_indicators": [],
            "artifacts": [],
        }
    metadata = dict(payload.get("metadata") or {})
    metadata.setdefault("section", section)
    artifacts = list(payload.get("artifacts") or metadata.get("artifacts") or [])
    source_file = metadata.get("source_file")
    if source_file and not any(item.get("path") == source_file for item in artifacts if isinstance(item, dict)):
        artifacts.append({"type": "source_file", "path": source_file})
    return {
        **payload,
        "metadata": metadata,
        "summary": dict(payload.get("summary") or {}),
        "findings": payload.get("findings") if isinstance(payload.get("findings"), dict) else {"items": payload.get("findings", [])},
        "risk_indicators": list(payload.get("risk_indicators") or []),
        "artifacts": artifacts,
    }


def normalize_frida_section(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {"findings": {"value": payload}}
    metadata = dict(payload.get("metadata") or {})
    metadata.setdefault("section", "frida")
    sessions = _normalize_frida_sessions(payload)
    sessions.sort(key=_frida_session_sort_key, reverse=True)
    aggregate_events: Dict[str, int] = {}
    risk_indicators = list(payload.get("risk_indicators") or [])
    artifacts = []
    for session in sessions:
        for tag, count in (session.get("events_by_tag") or {}).items():
            aggregate_events[str(tag)] = aggregate_events.get(str(tag), 0) + int(count)
        for artifact in session.get("artifacts") or []:
            if artifact not in artifacts:
                artifacts.append(artifact)
    source_file = metadata.get("source_file")
    if source_file and not any(item.get("path") == source_file for item in artifacts if isinstance(item, dict)):
        artifacts.append({"type": "source_file", "path": source_file})
    summary = dict(payload.get("summary") or {})
    summary.setdefault("session_count", len(sessions))
    summary.setdefault("hook_event_count", sum(int(session.get("hook_event_count", 0)) for session in sessions))
    summary.setdefault("error_count", sum(int(session.get("error_count", 0)) for session in sessions))
    return {
        **payload,
        "metadata": metadata,
        "summary": summary,
        "findings": {
            **(payload.get("findings") if isinstance(payload.get("findings"), dict) else {}),
            "sessions": sessions,
            "events_by_tag": aggregate_events,
        },
        "sessions": sessions,
        "risk_indicators": risk_indicators,
        "artifacts": artifacts,
    }


def _append_section_payload(section: str, existing: Any, incoming: Dict[str, Any]) -> Dict[str, Any]:
    if section == "frida":
        existing_section = normalize_frida_section(existing or {})
        incoming_section = normalize_frida_section(incoming)
        merged = {
            "metadata": {**existing_section.get("metadata", {}), **incoming_section.get("metadata", {})},
            "summary": {},
            "findings": {},
            "risk_indicators": [
                *list(existing_section.get("risk_indicators") or []),
                *list(incoming_section.get("risk_indicators") or []),
            ],
            "sessions": [
                *list(existing_section.get("sessions") or []),
                *list(incoming_section.get("sessions") or []),
            ],
        }
        return normalize_frida_section(merged)
    items = []
    if isinstance(existing, dict) and isinstance(existing.get("findings"), dict) and isinstance(existing["findings"].get("items"), list):
        items.extend(existing["findings"]["items"])
    elif existing is not None:
        items.append(existing)
    items.append(incoming)
    return {
        "metadata": {"section": section, "append_mode": True},
        "summary": {"item_count": len(items)},
        "findings": {"items": items},
        "risk_indicators": [],
        "artifacts": [],
    }


def _normalize_frida_sessions(payload: Dict[str, Any]) -> list[Dict[str, Any]]:
    sessions = payload.get("sessions")
    if isinstance(sessions, list):
        return [_normalize_frida_session_item(item, payload) for item in sessions if isinstance(item, dict)]
    findings = payload.get("findings") if isinstance(payload.get("findings"), dict) else {}
    if isinstance(findings.get("sessions"), list):
        return [_normalize_frida_session_item(item, payload) for item in findings["sessions"] if isinstance(item, dict)]
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    if not any([
        metadata.get("target"),
        metadata.get("script"),
        metadata.get("source_file"),
        findings.get("session"),
        findings.get("events_by_tag"),
        findings.get("hook_events"),
        findings.get("error_events"),
        payload.get("summary"),
    ]):
        return []
    return [_normalize_frida_session_item(payload, payload)]


def _normalize_frida_session_item(item: Dict[str, Any], parent_payload: Dict[str, Any]) -> Dict[str, Any]:
    source = deepcopy(item)
    metadata = dict(source.get("metadata") or {})
    parent_metadata = dict(parent_payload.get("metadata") or {})
    findings = source.get("findings") if isinstance(source.get("findings"), dict) else {}
    parent_findings = parent_payload.get("findings") if isinstance(parent_payload.get("findings"), dict) else {}
    session_blob = deepcopy(findings.get("session") or source.get("session") or {})
    summary = dict(source.get("summary") or parent_payload.get("summary") or {})
    events_by_tag = dict(findings.get("events_by_tag") or source.get("events_by_tag") or parent_findings.get("events_by_tag") or session_blob.get("events_by_tag") or {})
    hook_events = list(findings.get("hook_events") or source.get("hook_events") or parent_findings.get("hook_events") or [])
    error_events = list(findings.get("error_events") or source.get("error_events") or parent_findings.get("error_events") or [])
    artifacts = list(source.get("artifacts") or metadata.get("artifacts") or parent_payload.get("artifacts") or [])
    source_file = source.get("source_file") or metadata.get("source_file") or parent_metadata.get("source_file")
    if source_file and not any(artifact.get("path") == source_file for artifact in artifacts if isinstance(artifact, dict)):
        artifacts.append({"type": "source_file", "path": source_file})
    session = {
        **session_blob,
        "session_id": session_blob.get("session_id") or source.get("session_id") or source.get("target") or metadata.get("source_filename") or source_file,
        "target": session_blob.get("target") or source.get("target") or metadata.get("target") or parent_metadata.get("target"),
        "script": session_blob.get("script") or source.get("script") or metadata.get("script") or parent_metadata.get("script"),
        "status": session_blob.get("status") or source.get("status") or summary.get("status"),
        "summary": summary,
        "events_by_tag": events_by_tag,
        "hook_events": hook_events,
        "error_events": error_events,
        "artifacts": artifacts,
        "source_file": source_file,
        "started_at": session_blob.get("started_at") or source.get("started_at"),
        "ended_at": session_blob.get("ended_at") or source.get("ended_at"),
    }
    session["hook_event_count"] = int(events_by_tag.get("HOOK", len(hook_events)))
    session["error_count"] = len(error_events) or int(session_blob.get("stderr_lines", 0) or summary.get("stderr_lines", 0) or 0)
    return session


def _frida_session_sort_key(session: Dict[str, Any]) -> float:
    for key in ("ended_at", "started_at"):
        value = session.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return 0.0

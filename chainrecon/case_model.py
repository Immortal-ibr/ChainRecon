"""Portable, versioned evidence and investigation records.

Raw evidence is copied into content-addressed storage. The SQLite database is a
disposable index: ``case.json`` and the run documents remain the source of truth.
No source-machine paths are stored in a case manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
import uuid
from contextlib import closing
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal, cast

from chainrecon.analysis_catalog import BY_KIND


SCHEMA_VERSION = 2
RunStatus = Literal["complete", "partial", "failed", "needs_input"]
FindingStatus = Literal["candidate", "confirmed", "rejected"]
_RUN_STATUSES = {"complete", "partial", "failed", "needs_input"}
_FINDING_STATUSES = {"candidate", "confirmed", "rejected"}
_EVIDENCE_KINDS = set(BY_KIND)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _read_manifest(path: Path) -> dict[str, Any]:
    """Tolerate a brief sharing violation while a writer replaces the manifest."""
    for attempt in range(4):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except PermissionError:
            if attempt == 3:
                raise
            time.sleep(0.02 * (attempt + 1))
    raise AssertionError("unreachable")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class EvidenceRef:
    id: str
    sha256: str
    size: int
    kind: str
    name: str
    path: str
    added_at: str


@dataclass(frozen=True)
class Observation:
    id: str
    kind: str
    summary: str
    evidence_id: str
    locator: str
    confidence: Literal["low", "medium", "high"] = "medium"
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    status: FindingStatus = "candidate"
    observation_ids: tuple[str, ...] = ()
    rationale: str = ""
    affected_component: str = ""
    affected_versions: str = ""
    reproduction: str = ""
    impact: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunRecord:
    id: str
    analyzer: str
    status: RunStatus
    input_ids: tuple[str, ...]
    started_at: str
    completed_at: str
    tool_versions: dict[str, str] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    coverage: dict[str, Any] = field(default_factory=dict)
    observations: tuple[Observation, ...] = ()
    findings: tuple[Finding, ...] = ()
    artifacts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in _RUN_STATUSES:
            raise ValueError(f"Invalid run status: {self.status}")
        if any(item.status not in _FINDING_STATUSES for item in self.findings):
            raise ValueError("Invalid finding status")


class Case:
    """A portable case with immutable evidence and append-only run documents."""

    def __init__(self, root: Path, manifest: dict[str, Any]):
        self.root = root
        self.manifest = manifest

    @classmethod
    def create(cls, root: str | Path, title: str = "Untitled investigation") -> "Case":
        root = Path(root).expanduser().resolve()
        if (root / "case.json").exists():
            raise FileExistsError(f"A case already exists at {root}")
        root.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "case_id": str(uuid.uuid4()),
            "title": title,
            "created_at": _now(),
            "revision": 0,
            "evidence": [],
            "runs": [],
            "reviews": {},
            "review_history": [],
        }
        case = cls(root, manifest)
        case._save()
        case.rebuild_index()
        return case

    @classmethod
    def open(cls, root: str | Path) -> "Case":
        root = Path(root).expanduser().resolve()
        manifest = _read_manifest(root / "case.json")
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"Unsupported case schema: {manifest.get('schema_version')}")
        if not isinstance(manifest.get("evidence"), list) or not isinstance(manifest.get("runs"), list):
            raise ValueError("Case manifest has invalid evidence or run records")
        case = cls(root, manifest)
        if not (root / "index.sqlite3").exists():
            case.rebuild_index()
        return case

    def _save(self) -> None:
        current_path = self.root / "case.json"
        if current_path.exists():
            current = json.loads(current_path.read_text(encoding="utf-8"))
            if current.get("revision") != self.manifest["revision"]:
                raise RuntimeError("Case changed on disk; reopen it before writing")
        self.manifest["revision"] += 1
        snapshot = self.root / "manifests" / f"{self.manifest['revision']:06d}.json"
        _write_json_atomic(snapshot, self.manifest)
        _write_json_atomic(self.root / "case.json", self.manifest)

    def add_evidence(self, source: str | Path, *, kind: str = "other") -> EvidenceRef:
        if kind not in _EVIDENCE_KINDS:
            raise ValueError(f"Unsupported evidence kind: {kind}")
        source = Path(source).expanduser().resolve(strict=True)
        if not source.is_file():
            raise ValueError("Evidence source must be a regular file")
        destination_dir = self.root / "evidence" / "sha256"
        destination_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".import-", dir=destination_dir)
        try:
            with source.open("rb") as incoming, os.fdopen(fd, "wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            temporary = Path(tmp_name)
            digest = file_sha256(temporary)
            destination = destination_dir / digest
            if destination.exists():
                if destination.is_symlink():
                    raise ValueError("Evidence store contains a symlink")
                if file_sha256(destination) != digest:
                    raise ValueError("Existing evidence store content failed integrity check")
                temporary.unlink()
            else:
                os.replace(temporary, destination)
                destination.chmod(0o444)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        ref = EvidenceRef(
            id=f"ev-{digest}", sha256=digest, size=destination.stat().st_size,
            kind=kind, name=source.name,
            path=destination.relative_to(self.root).as_posix(), added_at=_now(),
        )
        for item in self.manifest["evidence"]:
            if item["id"] == ref.id:
                if item["kind"] != kind:
                    raise ValueError(f"This file is already imported as {item['kind']} evidence")
                return EvidenceRef(**item)
        self.manifest["evidence"].append(asdict(ref))
        self._save()
        self.rebuild_index()
        return ref

    def evidence(self, evidence_id: str) -> EvidenceRef:
        for item in self.manifest["evidence"]:
            if item["id"] == evidence_id:
                return EvidenceRef(**item)
        raise KeyError(f"Unknown evidence: {evidence_id}")

    def evidence_path(self, evidence_id: str, *, verify: bool = True) -> Path:
        ref = self.evidence(evidence_id)
        if not re.fullmatch(r"[0-9a-f]{64}", ref.sha256) or ref.id != f"ev-{ref.sha256}" or ref.path != f"evidence/sha256/{ref.sha256}":
            raise ValueError("Invalid evidence reference in case manifest")
        path = self.root / ref.path
        if path.is_symlink() or (verify and (not path.is_file() or file_sha256(path) != ref.sha256)):
            raise ValueError(f"Evidence integrity check failed: {evidence_id}")
        return path

    def add_run(self, run: RunRecord) -> None:
        if not re.fullmatch(r"run-[0-9a-f]{32}", run.id):
            raise ValueError("Invalid run ID")
        if any(item["id"] == run.id for item in self.manifest["runs"]):
            raise ValueError(f"Run ID already exists: {run.id}")
        if not run.input_ids:
            raise ValueError("A run must reference input evidence")
        for evidence_id in run.input_ids:
            self.evidence_path(evidence_id)
        observation_ids = [item.id for item in run.observations]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("Duplicate observation IDs in run")
        if any(item.evidence_id not in run.input_ids for item in run.observations):
            raise ValueError("Observation references evidence outside run inputs")
        finding_ids = [item.id for item in run.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("Duplicate finding IDs in run")
        if any(not item.observation_ids or any(oid not in observation_ids for oid in item.observation_ids) for item in run.findings):
            raise ValueError("Every finding must link to observations in its run")
        path = self.root / "runs" / run.id / "run.json"
        _write_json_atomic(path, asdict(run))
        self.manifest["runs"].append({
            "id": run.id, "analyzer": run.analyzer, "status": run.status,
            "path": path.relative_to(self.root).as_posix(),
        })
        self._save()
        self.rebuild_index()

    def get_run(self, run_id: str) -> dict[str, Any]:
        for item in self.manifest["runs"]:
            if item["id"] == run_id:
                if not re.fullmatch(r"run-[0-9a-f]{32}", run_id) or item["path"] != f"runs/{run_id}/run.json":
                    raise ValueError("Invalid run reference in case manifest")
                return json.loads((self.root / item["path"]).read_text(encoding="utf-8"))
        raise KeyError(f"Unknown run: {run_id}")

    def review_finding(self, finding_id: str, status: FindingStatus, *, note: str = "", reviewer: str = "") -> None:
        if status not in _FINDING_STATUSES:
            raise ValueError(f"Invalid finding status: {status}")
        if not any(finding["id"] == finding_id for run in self.iter_runs() for finding in run["findings"]):
            raise KeyError(f"Unknown finding: {finding_id}")
        decision = {"finding_id": finding_id, "status": status, "note": note, "reviewer": reviewer, "reviewed_at": _now()}
        self.manifest["reviews"][finding_id] = decision
        self.manifest.setdefault("review_history", []).append(decision)
        self._save()
        self.rebuild_index()

    def iter_runs(self) -> Iterable[dict[str, Any]]:
        for item in self.manifest["runs"]:
            yield self.get_run(item["id"])

    def rebuild_index(self) -> None:
        """Recreate the disposable query index from manifest and run documents."""
        path = self.root / "index.sqlite3"
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
                DROP TABLE IF EXISTS evidence;
                DROP TABLE IF EXISTS runs;
                DROP TABLE IF EXISTS observations;
                DROP TABLE IF EXISTS findings;
                CREATE TABLE evidence (id TEXT PRIMARY KEY, sha256 TEXT, kind TEXT, name TEXT, size INTEGER);
                CREATE TABLE runs (id TEXT PRIMARY KEY, analyzer TEXT, status TEXT, completed_at TEXT);
                CREATE TABLE observations (id TEXT PRIMARY KEY, run_id TEXT, kind TEXT, summary TEXT, evidence_id TEXT, locator TEXT, confidence TEXT);
                CREATE TABLE findings (id TEXT PRIMARY KEY, run_id TEXT, title TEXT, severity TEXT, status TEXT, rationale TEXT);
                CREATE INDEX observations_evidence ON observations(evidence_id);
                CREATE INDEX observations_kind ON observations(kind);
                CREATE INDEX findings_status ON findings(status);
            """)
            db.executemany("INSERT INTO evidence VALUES (:id,:sha256,:kind,:name,:size)", self.manifest["evidence"])
            for run in self.iter_runs():
                db.execute("INSERT INTO runs VALUES (?,?,?,?)", (run["id"], run["analyzer"], run["status"], run["completed_at"]))
                db.executemany(
                    "INSERT INTO observations VALUES (?,?,?,?,?,?,?)",
                    [(o["id"], run["id"], o["kind"], o["summary"], o["evidence_id"], o["locator"], o["confidence"]) for o in run["observations"]],
                )
                db.executemany(
                    "INSERT INTO findings VALUES (?,?,?,?,?,?)",
                    [(f["id"], run["id"], f["title"], f["severity"], self.manifest["reviews"].get(f["id"], {}).get("status", f["status"]), f["rationale"]) for f in run["findings"]],
                )

    def query(self, table: Literal["evidence", "runs", "observations", "findings"], *, limit: int = 1000) -> list[dict[str, Any]]:
        if table not in {"evidence", "runs", "observations", "findings"}:
            raise ValueError("Unsupported query table")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10_000:
            raise ValueError("Query limit must be between 1 and 10,000")
        with closing(sqlite3.connect(self.root / "index.sqlite3")) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(f"SELECT * FROM {table} LIMIT ?", (limit,))]


def record_legacy_result(case: Case, evidence_id: str, result: dict[str, Any], *, analyzer: str) -> RunRecord:
    """Import a v1 result conservatively; all risk indicators need review."""
    started = _now()
    observations: list[Observation] = []
    findings: list[Finding] = []
    run_id = f"run-{uuid.uuid4().hex}"
    legacy_findings = result.get("findings") or {}
    if isinstance(legacy_findings, list):
        legacy_findings = {"items": legacy_findings}
    if not isinstance(legacy_findings, dict):
        legacy_findings = {"value": legacy_findings}
    for key, value in legacy_findings.items():
        count = len(value) if isinstance(value, (list, dict)) else 1
        observations.append(Observation(
            id=f"obs-{uuid.uuid4().hex}", kind=f"legacy.{key}",
            summary=f"Imported {key}: {count} item(s)", evidence_id=evidence_id,
            locator=f"findings.{key}", confidence="low", attributes={"count": count},
        ))
    for index, item in enumerate(result.get("risk_indicators") or []):
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "info")).lower()
        if severity not in {"info", "low", "medium", "high", "critical"}:
            severity = "info"
        indicator_observation = Observation(
            id=f"obs-{uuid.uuid4().hex}", kind="legacy.risk_indicator",
            summary=f"Imported risk indicator {index + 1}", evidence_id=evidence_id,
            locator=f"risk_indicators[{index}]", confidence="low",
        )
        observations.append(indicator_observation)
        findings.append(Finding(
            id=f"finding-{uuid.uuid4().hex}", title=str(item.get("title") or "Legacy risk indicator"),
            severity=cast(Literal["info", "low", "medium", "high", "critical"], severity), status="candidate", observation_ids=(indicator_observation.id,),
            rationale=f"Imported from risk_indicators[{index}]; requires independent verification.",
        ))
    run = RunRecord(
        id=run_id, analyzer=analyzer, status="complete", input_ids=(evidence_id,),
        started_at=started, completed_at=_now(), warnings=("Version 1 results were imported as unverified observations.",),
        coverage={"legacy_result_imported": True, "source_analysis_reexecuted": False},
        observations=tuple(observations), findings=tuple(findings),
    )
    case.add_run(run)
    return run

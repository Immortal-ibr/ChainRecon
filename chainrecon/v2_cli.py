"""Case-first ChainRecon 2.0 commands; v1 commands remain compatibility paths."""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from typing import Sequence, cast

from chainrecon.analysis_catalog import ANALYZER_KINDS, BY_KIND
from chainrecon.case_analysis import CaseAnalysisService, analyze_evidence
from chainrecon.case_model import Case, FindingStatus, record_legacy_result
from chainrecon.firmware_engine import FirmwareEngine
from chainrecon.utils.config import get_case_directory, get_firmware_mode


def _print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _case_path(argument: str | None) -> str:
    """Use the explicit case or the configured default."""
    path = argument or get_case_directory()
    if path is None:
        raise ValueError("Case folder is required; pass it or set case.directory in the configuration")
    return str(path)


def _evidence_id(case: Case, explicit: str | None, analyzer: str) -> str:
    """Select the only compatible input, or ask for an explicit choice."""
    if explicit:
        case.evidence(explicit)
        return explicit
    kinds = (set().union(*ANALYZER_KINDS.values()) if analyzer == "auto"
             else ANALYZER_KINDS[analyzer])
    matches = [item for item in case.manifest["evidence"] if item["kind"] in kinds]
    if len(matches) == 1:
        return str(matches[0]["id"])
    if not matches:
        raise ValueError(f"No {analyzer} evidence in the case; import a source file first")
    names = ", ".join(str(item["name"]) for item in matches[:5])
    raise ValueError(f"Multiple {analyzer} evidence files: {names}; choose an evidence ID from 'case list evidence'")


def _optional_case_positionals(case_value: str | None, *required: str | None) -> tuple[str | None, tuple[str, ...]]:
    """Accept both case-first and case-free forms of a command."""
    values = [case_value, *required]
    if values[-1] is None:
        values = [None, *values[:-1]]
    if any(value is None for value in values[1:]):
        raise ValueError("Missing required command argument")
    return values[0], tuple(str(value) for value in values[1:])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chainrecon", description="Portable IoT investigation cases")
    commands = parser.add_subparsers(dest="command", required=True)
    case = commands.add_parser("case")
    case_commands = case.add_subparsers(dest="case_command", required=True)
    init = case_commands.add_parser("init")
    init.add_argument("path", nargs="?")
    init.add_argument("--title", default="Untitled investigation")
    add = case_commands.add_parser("add")
    add.add_argument("case", nargs="?")
    add.add_argument("source", nargs="?")
    add.add_argument("--kind", choices=sorted(BY_KIND), default="other")
    listing = case_commands.add_parser("list")
    listing.add_argument("case", nargs="?")
    listing.add_argument("table", choices=["evidence", "runs", "observations", "findings"], nargs="?", default="evidence")
    verify = case_commands.add_parser("verify")
    verify.add_argument("case", nargs="?")
    reindex = case_commands.add_parser("reindex")
    reindex.add_argument("case", nargs="?")
    review = case_commands.add_parser("review")
    review.add_argument("case", nargs="?")
    review.add_argument("finding_id", nargs="?")
    review.add_argument("status", nargs="?", choices=["candidate", "confirmed", "rejected"])
    review.add_argument("--note", default="")
    review.add_argument("--reviewer", default="")
    migrate = case_commands.add_parser("import-v1")
    migrate.add_argument("case", nargs="?")
    migrate.add_argument("result_json", nargs="?")
    migrate.add_argument("--analyzer", default="v1-import")
    analyze = case_commands.add_parser("analyze")
    analyze.add_argument("case", nargs="?")
    analyze.add_argument("evidence_id", nargs="?")
    analyze.add_argument("--analyzer", choices=["auto", *sorted(ANALYZER_KINDS)], default="auto")

    firmware = commands.add_parser("firmware")
    firmware_commands = firmware.add_subparsers(dest="firmware_command", required=True)
    fw_analyze = firmware_commands.add_parser("analyze")
    fw_analyze.add_argument("case", nargs="?", help="Case folder; defaults to case.directory in configuration")
    fw_analyze.add_argument("evidence_id", nargs="?", help="Internal evidence reference; inferred for a single firmware image")
    fw_analyze.add_argument("--mode", choices=["container", "trusted-wsl", "trusted-host"])
    fw_analyze.add_argument("--advisory-snapshot")
    fw_diff = firmware_commands.add_parser("diff")
    fw_diff.add_argument("case", nargs="?")
    fw_diff.add_argument("before_run", nargs="?")
    fw_diff.add_argument("after_run", nargs="?")
    fw_emulate = firmware_commands.add_parser("emulate")
    fw_emulate.add_argument("case", nargs="?")
    fw_emulate.add_argument("run_id", nargs="?")
    fw_emulate.add_argument("binary", nargs="?", help="Path inside extracted firmware")
    fw_emulate.add_argument("--rootfs", help="Matching root filesystem path inside extraction; inferred when omitted")
    fw_emulate.add_argument("--arg", action="append", default=[])
    fw_emulate.add_argument("--timeout", type=int, default=30)

    workflow = commands.add_parser("workflow")
    workflow_commands = workflow.add_subparsers(dest="workflow_command", required=True)
    plan = workflow_commands.add_parser("plan")
    plan.add_argument("pipeline")
    plan.add_argument("--target")
    plan.add_argument("--profile")
    plan.add_argument("--device-profile")
    plan.add_argument("--input", action="append", default=[], metavar="NAME=VALUE")
    run = workflow_commands.add_parser("run")
    run.add_argument("pipeline")
    run.add_argument("--target")
    run.add_argument("--profile")
    run.add_argument("--device-profile")
    run.add_argument("--input", action="append", default=[], metavar="NAME=VALUE")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--case", help="Record execution in a portable case")
    run.add_argument("--evidence-id", action="append", default=[], help="Additional already-imported workflow input")
    resume = workflow_commands.add_parser("resume")
    resume.add_argument("pipeline")
    resume.add_argument("--resume-file", required=True)
    resume.add_argument("--approve-step", action="append", default=[])
    resume.add_argument("--target")
    resume.add_argument("--profile")
    resume.add_argument("--device-profile")
    resume.add_argument("--input", action="append", default=[], metavar="NAME=VALUE")
    resume.add_argument("--case", help="Record the resumed execution in a portable case")
    resume.add_argument("--evidence-id", action="append", default=[], help="Additional already-imported workflow input")

    report = commands.add_parser("report")
    report_commands = report.add_subparsers(dest="report_command", required=True)
    export = report_commands.add_parser("export")
    export.add_argument("case", nargs="?")
    export.add_argument("--format", choices=["json", "html", "csv", "xlsx"], default="html")
    export.add_argument("--output", required=True)
    return parser


def dispatch(argv: Sequence[str]) -> int | None:
    """Handle new subcommands and leave version 1 syntax to the old parser."""
    if not argv:
        return None
    if argv[0] == "case" or (len(argv) > 1 and (argv[0], argv[1]) in {
        ("firmware", "analyze"), ("firmware", "diff"), ("firmware", "emulate"),
        ("workflow", "plan"), ("workflow", "run"), ("workflow", "resume"), ("report", "export"),
    }):
        args = _parser().parse_args(list(argv))
    else:
        return None
    if args.command == "case":
        if args.case_command == "init":
            case = Case.create(_case_path(args.path), args.title)
            _print({"case_id": case.manifest["case_id"], "case": str(case.root)})
        elif args.case_command == "add":
            case_arg, (source,) = _optional_case_positionals(args.case, args.source)
            _print(Case.open(_case_path(case_arg)).add_evidence(source, kind=args.kind).__dict__)
        elif args.case_command == "list":
            table = args.table
            case_arg = args.case
            if case_arg in {"evidence", "runs", "observations", "findings"} and table == "evidence":
                table, case_arg = case_arg, None
            _print(Case.open(_case_path(case_arg)).query(table))
        elif args.case_command == "verify":
            case = Case.open(_case_path(args.case))
            for evidence in case.manifest["evidence"]:
                case.evidence_path(evidence["id"])
            _print({"verified": len(case.manifest["evidence"])})
        elif args.case_command == "reindex":
            case = Case.open(_case_path(args.case))
            case.rebuild_index()
            _print({"reindexed": True, "runs": len(case.manifest["runs"])})
        elif args.case_command == "review":
            case_arg, (finding_id, status) = _optional_case_positionals(args.case, args.finding_id, args.status)
            if status not in {"candidate", "confirmed", "rejected"}:
                raise ValueError("Status must be candidate, confirmed, or rejected")
            case = Case.open(_case_path(case_arg))
            case.review_finding(finding_id, cast(FindingStatus, status), note=args.note, reviewer=args.reviewer)
            _print({"finding_id": finding_id, "status": status})
        elif args.case_command == "import-v1":
            case_arg, (result_json,) = _optional_case_positionals(args.case, args.result_json)
            case = Case.open(_case_path(case_arg))
            evidence = case.add_evidence(result_json, kind="legacy_result")
            result = json.loads(case.evidence_path(evidence.id).read_text(encoding="utf-8"))
            run = record_legacy_result(case, evidence.id, result, analyzer=args.analyzer)
            _print({"run_id": run.id, "status": run.status, "candidate_findings": len(run.findings)})
        elif args.case_command == "analyze":
            case_arg, evidence_arg = args.case, args.evidence_id
            if case_arg and case_arg.startswith("ev-") and evidence_arg is None:
                case_arg, evidence_arg = None, case_arg
            case = Case.open(_case_path(case_arg))
            chosen_id = _evidence_id(case, evidence_arg, args.analyzer)
            run = analyze_evidence(case, chosen_id, analyzer=None if args.analyzer == "auto" else args.analyzer,
                                   firmware_mode=get_firmware_mode())
            _print({"run_id": run.id, "status": run.status, "coverage": run.coverage, "warnings": run.warnings})
    elif args.command == "firmware":
        case_arg = args.case
        evidence_arg = getattr(args, "evidence_id", None)
        if args.firmware_command == "analyze" and case_arg and case_arg.startswith("ev-") and evidence_arg is None:
            case_arg, evidence_arg = None, case_arg
        if args.firmware_command == "diff":
            case_arg, (before_run, after_run) = _optional_case_positionals(case_arg, args.before_run, args.after_run)
        elif args.firmware_command == "emulate":
            case_arg, (run_id, binary) = _optional_case_positionals(case_arg, args.run_id, args.binary)
        case = Case.open(_case_path(case_arg))
        engine = FirmwareEngine()
        if args.firmware_command == "analyze":
            run = engine.analyze(case, _evidence_id(case, evidence_arg, "firmware"), mode=args.mode or get_firmware_mode(), advisory_snapshot=args.advisory_snapshot)
            _print({"run_id": run.id, "status": run.status, "coverage": run.coverage, "warnings": run.warnings})
        elif args.firmware_command == "diff":
            _print(engine.diff(case, before_run, after_run))
        else:
            _print(engine.emulate(case, run_id, binary, rootfs=args.rootfs, argv=args.arg, timeout=args.timeout))
    elif args.command == "workflow":
        from chainrecon.runners.workflow_runner import WorkflowRunner
        values = {}
        for assignment in args.input:
            if "=" not in assignment:
                raise ValueError(f"Workflow input must be NAME=VALUE: {assignment}")
            name, value = assignment.split("=", 1)
            if not name:
                raise ValueError("Workflow input name cannot be empty")
            values[name] = value
        workflow_case_path = getattr(args, "case", None) or (
            get_case_directory() if args.workflow_command != "plan" else None
        )
        workflow_case = Case.open(workflow_case_path) if workflow_case_path and not getattr(args, "dry_run", False) else None
        workflow_run_id = f"run-{uuid.uuid4().hex}" if workflow_case else None
        pipeline_ref = workflow_case.add_evidence(args.pipeline, kind="other") if workflow_case else None
        input_ids = (pipeline_ref.id, *args.evidence_id) if workflow_case and pipeline_ref else ()
        if workflow_case:
            for evidence_id in input_ids:
                workflow_case.evidence_path(evidence_id)
        runner = WorkflowRunner(output_root=workflow_case.root / "runs" / workflow_run_id / "artifacts" if workflow_case and workflow_run_id else None, case=workflow_case)
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result = runner.run(
            str(workflow_case.evidence_path(pipeline_ref.id)) if workflow_case and pipeline_ref else args.pipeline,
            target=args.target, profile=args.profile,
            device_profile=args.device_profile, dry_run=args.workflow_command == "plan" or bool(getattr(args, "dry_run", False)),
            resume_file=getattr(args, "resume_file", None),
            approved_steps=getattr(args, "approve_step", None),
            inputs=values,
        )
        if workflow_case and workflow_run_id:
            recorded = CaseAnalysisService(workflow_case).record_workflow(workflow_run_id, input_ids, result, started_at=started)
            result["metadata"]["case_run_id"] = recorded.id
        _print(result)
        return 1 if result.get("summary", {}).get("status") in {"failed", "partial", "completed_with_errors"} else 0
    else:
        from chainrecon.case_reporting import export_case_report
        case = Case.open(_case_path(args.case))
        output = export_case_report(case, args.format, args.output)
        _print({"output": str(output), "format": args.format})
    return 0

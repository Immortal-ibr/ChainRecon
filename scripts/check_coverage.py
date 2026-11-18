"""Enforce the ChainRecon 2.0 release coverage gates from coverage JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path


GROUPS = {
    "case": ("chainrecon/case_model.py", "chainrecon/case_analysis.py", "chainrecon/case_reporting.py"),
    "firmware": ("chainrecon/firmware_engine.py", "chainrecon/elf_inspection.py"),
    "workflow": ("chainrecon/runners/workflow_runner.py",),
}


def main(path: str) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    totals = data["totals"]
    line_coverage = 100 * totals["covered_lines"] / max(1, totals["num_statements"])
    failures = []
    print(f"Overall line coverage: {line_coverage:.1f}% (required: 80%)")
    if line_coverage < 80:
        failures.append("overall line coverage")
    files = {name.replace("\\", "/"): value["summary"] for name, value in data["files"].items()}
    for label, suffixes in GROUPS.items():
        summaries = [files[path] for path in suffixes if path in files]
        if len(summaries) != len(suffixes):
            failures.append(f"{label} file coverage missing")
            continue
        branches = sum(item["num_branches"] for item in summaries)
        covered = sum(item["covered_branches"] for item in summaries)
        percent = 100 * covered / max(1, branches)
        print(f"{label.title()} branch coverage: {percent:.1f}% (required: 90%)")
        if percent < 90:
            failures.append(f"{label} branch coverage")
    if failures:
        print("Release gates failed: " + ", ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))

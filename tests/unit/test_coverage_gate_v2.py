"""Release coverage checks identify core modules by path."""

import json
from pathlib import Path

from scripts.check_coverage import main


def test_tui_module_with_same_basename_does_not_distort_core_gate(tmp_path: Path) -> None:
    files = {
        "chainrecon\\case_model.py": {"summary": {"covered_branches": 9, "num_branches": 10}},
        "chainrecon\\case_analysis.py": {"summary": {"covered_branches": 9, "num_branches": 10}},
        "chainrecon\\case_reporting.py": {"summary": {"covered_branches": 9, "num_branches": 10}},
        "chainrecon\\firmware_engine.py": {"summary": {"covered_branches": 9, "num_branches": 10}},
        "chainrecon\\elf_inspection.py": {"summary": {"covered_branches": 9, "num_branches": 10}},
        "chainrecon\\runners\\workflow_runner.py": {"summary": {"covered_branches": 9, "num_branches": 10}},
        "chainrecon\\tui\\screens\\case_analysis.py": {"summary": {"covered_branches": 0, "num_branches": 10}},
    }
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps({"totals": {"covered_lines": 80, "num_statements": 100}, "files": files}),
                    encoding="utf-8")
    assert main(str(path)) == 0

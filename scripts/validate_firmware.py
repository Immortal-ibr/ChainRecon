"""Run a disposable local case against a known firmware image."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from chainrecon.case_model import Case, file_sha256
from chainrecon.firmware_engine import FirmwareEngine


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--mode", choices=("container", "trusted-wsl", "trusted-host"), default="container")
    args = parser.parse_args()
    image = args.image.expanduser().resolve(strict=True)
    digest = file_sha256(image)
    if args.expected_sha256 and digest.lower() != args.expected_sha256.lower():
        raise ValueError(f"Image hash mismatch: {digest}")
    with tempfile.TemporaryDirectory(prefix="chainrecon-firmware-validation-") as directory:
        case = Case.create(Path(directory) / "case", "Local firmware validation")
        evidence = case.add_evidence(image, kind="firmware")
        run = FirmwareEngine().analyze(case, evidence.id, mode=args.mode)
        print(json.dumps({
            "sha256": digest,
            "mode": args.mode,
            "status": run.status,
            "regular_files": run.coverage["regular_files"],
            "elf_files": run.coverage["elf_files"],
            "certificates": run.coverage["certificates"],
            "certificate_parse_errors": run.coverage["certificate_parse_errors"],
            "candidate_findings": len(run.findings),
            "candidate_titles": [finding.title for finding in run.findings[:10]],
            "extraction_completed": run.coverage["extraction_completed"],
            "warnings": list(run.warnings[:10]),
        }, sort_keys=True))
        return 0 if run.status == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())

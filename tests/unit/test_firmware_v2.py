"""Firmware parser, extraction boundary, inventory, and emulation gates."""

from __future__ import annotations

import json
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from chainrecon.case_model import Case
from chainrecon.elf_inspection import inspect_elf
from chainrecon.firmware_engine import FirmwareEngine, _safe_child, _walk_regular, identify_image


def _minimal_mips_elf() -> bytes:
    data = bytearray(52)
    data[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 8, 1)
    struct.pack_into("<HHHH", data, 42, 32, 0, 40, 0)
    return bytes(data)


def _minimal_arm_elf() -> bytes:
    data = bytearray(_minimal_mips_elf())
    struct.pack_into("<H", data, 18, 40)
    return bytes(data)


def _test_certificate() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "camera.example.test")])
    return (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
            .sign(key, hashes.SHA256()))


def _elf_with_loader_and_dependencies() -> bytes:
    data = bytearray(512)
    data[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<HHI", data, 16, 3, 8, 1)
    struct.pack_into("<II", data, 28, 52, 160)
    struct.pack_into("<HHHH", data, 42, 32, 3, 40, 2)
    interpreter = b"/lib/ld.so.1\x00"
    data[256:256 + len(interpreter)] = interpreter
    struct.pack_into("<IIIIIIII", data, 52, 3, 256, 0, 0, len(interpreter), len(interpreter), 4, 1)
    struct.pack_into("<IIIIIIII", data, 84, 0x6474E551, 0, 0, 0, 0, 0, 6, 1)
    struct.pack_into("<IIIIIIII", data, 116, 0x6474E552, 0, 0, 0, 0, 0, 4, 1)
    strings = b"\x00libc.so.6\x00"
    data[384:384 + len(strings)] = strings
    struct.pack_into("<IIIIIIIIII", data, 160, 0, 3, 0, 0, 384, len(strings), 0, 0, 1, 0)
    struct.pack_into("<IIIIIIIIII", data, 200, 0, 6, 0, 0, 320, 24, 0, 0, 4, 8)
    struct.pack_into("<IIIIII", data, 320, 1, 1, 24, 0, 0, 0)
    return bytes(data)


def test_elf_inspection_reports_loader_dependencies_and_hardening(tmp_path: Path) -> None:
    path = tmp_path / "service.elf"
    path.write_bytes(_elf_with_loader_and_dependencies())
    details = inspect_elf(path)
    assert details == {"interpreter": "/lib/ld.so.1", "needed": ["libc.so.6"], "pie": True, "nx_stack": True, "relro": "full", "parse_status": "complete"}


def test_elf_inspection_marks_malformed_tables_partial(tmp_path: Path) -> None:
    data = bytearray(_elf_with_loader_and_dependencies())
    struct.pack_into("<H", data, 44, 513)
    path = tmp_path / "invalid-ph.elf"
    path.write_bytes(data)
    assert inspect_elf(path)["parse_status"] == "partial"
    data = bytearray(_elf_with_loader_and_dependencies())
    struct.pack_into("<I", data, 32, 500)
    path.write_bytes(data)
    assert inspect_elf(path)["parse_status"] == "partial"
    path.write_bytes(b"not an ELF")
    assert inspect_elf(path) is None


def test_identify_validated_squashfs_partition_and_architecture(tmp_path: Path) -> None:
    image = bytearray(4096)
    image[:52] = _minimal_mips_elf()
    image[510:512] = b"\x55\xaa"
    image[446 + 4] = 0x83
    struct.pack_into("<II", image, 446 + 8, 1, 2)
    offset = 1024
    image[offset:offset + 4] = b"hsqs"
    struct.pack_into("<I", image, offset + 12, 4096)
    struct.pack_into("<H", image, offset + 28, 4)
    struct.pack_into("<Q", image, offset + 40, 96)
    path = tmp_path / "firmware.bin"
    path.write_bytes(image)
    result = identify_image(path)
    assert result["elf"]["machine"] == "mips"
    assert result["partitions"][0]["offset"] == 512
    assert any(item["type"] == "squashfs" and item["offset"] == offset and item["validated"] for item in result["signatures"])
    assert not result["signature_truncated"]
    assert inspect_elf(tmp_path / "firmware.bin")["parse_status"] == "complete"


def test_invalid_squashfs_magic_is_not_treated_as_filesystem(tmp_path: Path) -> None:
    path = tmp_path / "opaque.bin"
    path.write_bytes(b"random\x00hsqs" + b"\x00" * 128)
    result = identify_image(path)
    assert not any(item["type"] == "squashfs" for item in result["signatures"])


def test_safe_walk_skips_symlink_and_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "real.txt").write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("not part of firmware", encoding="utf-8")
    try:
        (root / "link.txt").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable on this platform")
    warnings: list[str] = []
    assert [path.name for path in _walk_regular(root, warnings)] == ["real.txt"]
    assert any("Skipped" in warning for warning in warnings)
    with pytest.raises(ValueError):
        _safe_child(root, "../outside.txt")
    with pytest.raises(ValueError):
        _safe_child(root, "link.txt")
    (root / "actual").mkdir()
    (root / "actual/service").write_bytes(_minimal_mips_elf())
    (root / "internal-link").symlink_to(root / "actual", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        _safe_child(root, "internal-link/service")
    warnings.clear()
    assert "actual/service" in {path.relative_to(root).as_posix() for path in _walk_regular(root, warnings)}
    assert any("Skipped directory symlink" in warning for warning in warnings)


def _make_case(tmp_path: Path, name: str = "image.bin") -> tuple[Case, str]:
    image = tmp_path / name
    image.write_bytes(b"opaque test image")
    case = Case.create(tmp_path / "case")
    ref = case.add_evidence(image, kind="firmware")
    return case, ref.id


def test_container_unavailable_records_needs_input_without_claiming_absence(tmp_path: Path) -> None:
    case, evidence_id = _make_case(tmp_path)
    with patch("chainrecon.firmware_engine.shutil.which", return_value=None):
        run = FirmwareEngine().analyze(case, evidence_id)
    assert run.status == "needs_input"
    assert not run.coverage["extraction_completed"]
    assert run.coverage["regular_files"] == 0
    assert run.findings == ()


def test_firmware_inventory_and_exact_advisory_match(tmp_path: Path) -> None:
    case, evidence_id = _make_case(tmp_path)
    certificate = _test_certificate()
    snapshot = tmp_path / "advisories.json"
    snapshot.write_text(json.dumps({"advisories": [{"id": "TEST-2026-1", "component": "sampled", "versions": ["1.2.3"]}, {"id": "TEST-2026-2", "component": "sampled", "versions": ["9.9.9"]}]}), encoding="utf-8")

    def extraction(_source: Path, root: Path, _mode: str, _warnings: list[str]) -> tuple[str, str]:
        fs = root / "squashfs-root"
        (fs / "etc").mkdir(parents=True)
        (fs / "usr/lib/opkg").mkdir(parents=True)
        (fs / "usr/sbin").mkdir(parents=True)
        (fs / "etc/certs").mkdir(parents=True)
        (fs / "etc/shadow").write_text("root:$1$withheld$hash:0:0\nlocked:!:0:0\n", encoding="utf-8")
        (fs / "etc/config").write_text("api_key=sample-secret\nserver=https://user:pass@example.test/api?access_token=hidden\nmqtt=mqtts://broker.example.test:8883/topic\nstream=rtsp://camera.example.test/live\n", encoding="utf-8")
        (fs / "etc/key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nkey bytes\n-----END RSA PRIVATE KEY-----\n", encoding="utf-8")
        (fs / "etc/certs/server.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (fs / "etc/certs/backup.der").write_bytes(certificate.public_bytes(serialization.Encoding.DER))
        (fs / "usr/lib/opkg/status").write_text("Package: sampled\nVersion: 1.2.3\n", encoding="utf-8")
        (fs / "usr/sbin/dropbear").write_bytes(_minimal_mips_elf())
        return "complete", ""

    engine = FirmwareEngine()
    progress: list[str] = []
    with patch.object(engine, "_extract", side_effect=extraction):
        run = engine.analyze(case, evidence_id, advisory_snapshot=snapshot, progress=progress.append)
    assert run.status == "complete"
    assert progress[:3] == ["Identifying firmware image", "Extracting with container mode", "Inventorying recovered files"]
    assert progress[-1].endswith("7 files inventoried")
    assert run.coverage["regular_files"] == 7
    assert run.coverage["elf_files"] == 1
    assert run.coverage["certificates"] == 2
    assert run.coverage["certificate_parse_errors"] == 0
    assert len([item for item in run.observations if item.kind == "firmware.certificate"]) == 2
    assert all(item.attributes["fingerprint_sha256"] == certificate.fingerprint(hashes.SHA256()).hex() for item in run.observations if item.kind == "firmware.certificate")
    endpoints = [item.attributes for item in run.observations if item.kind == "firmware.endpoint"]
    assert {item["scheme"] for item in endpoints} == {"https", "mqtts", "rtsp"}
    assert any(item["host"] == "broker.example.test" and item["port"] == 8883 for item in endpoints)
    assert all("url" not in item and "user" not in json.dumps(item) and "hidden" not in json.dumps(item) for item in endpoints)
    assert any(item.kind == "firmware.password_hash_type" and item.attributes["scheme"] == "md5-crypt" for item in run.observations)
    assert any(item.kind == "firmware.advisory_match" and item.attributes["advisory_id"] == "TEST-2026-1" for item in run.observations)
    assert not any(item.attributes.get("advisory_id") == "TEST-2026-2" for item in run.observations)
    assert len(run.input_ids) == 2
    assert case.evidence_path(run.input_ids[1]).read_bytes() == snapshot.read_bytes()
    assert run.settings["advisory_snapshot_sha256"] == case.evidence(run.input_ids[1]).sha256
    advisory_finding = next(item for item in run.findings if "TEST-2026-1" in item.title)
    linked = {item.id: item for item in run.observations}
    assert {linked[oid].evidence_id for oid in advisory_finding.observation_ids} == set(run.input_ids)
    assert all(item.status == "candidate" for item in run.findings)
    inspection = json.loads((case.root / run.artifacts[0]).read_text(encoding="utf-8"))
    assert "sample-secret" not in json.dumps(inspection)
    assert "key bytes" not in json.dumps(inspection)


def test_malformed_certificate_is_recorded_as_incomplete_inventory(tmp_path: Path) -> None:
    case, evidence_id = _make_case(tmp_path)
    engine = FirmwareEngine()

    def extraction(_source: Path, root: Path, _mode: str, _warnings: list[str]) -> tuple[str, str]:
        root.mkdir(parents=True)
        (root / "bad.crt").write_bytes(b"not a DER certificate")
        return "complete", ""

    with patch.object(engine, "_extract", side_effect=extraction):
        run = engine.analyze(case, evidence_id)
    assert run.status == "partial"
    assert run.coverage["certificate_parse_errors"] == 1
    assert not any(item.kind == "firmware.certificate" for item in run.observations)
    assert any("bad.crt" in warning for warning in run.warnings)


def test_firmware_diff_and_emulation_boundary(tmp_path: Path) -> None:
    case, evidence_id = _make_case(tmp_path)
    engine = FirmwareEngine()
    phase = {"value": 1}

    def extraction(_source: Path, root: Path, _mode: str, _warnings: list[str]) -> tuple[str, str]:
        (root / "boot").mkdir(parents=True)
        (root / "etc").mkdir()
        (root / "lib").mkdir()
        (root / "boot/daemon").write_bytes(_minimal_mips_elf())
        (root / "version.txt").write_text(str(phase["value"]), encoding="utf-8")
        return "complete", ""

    with patch.object(engine, "_extract", side_effect=extraction):
        first = engine.analyze(case, evidence_id)
        phase["value"] = 2
        second = engine.analyze(case, evidence_id)
    diff = engine.diff(case, first.id, second.id)
    assert any(path.endswith("version.txt") for path in diff["changed"])
    assert diff["unchanged_count"] == 1
    with patch.object(engine, "_container_ready", return_value=(True, "")), patch("chainrecon.firmware_engine._result", return_value=subprocess.CompletedProcess(["docker"], 1, "", "missing loader")) as run_tool:
        outcome = engine.emulate(case, second.id, "boot/daemon")
    assert outcome["status"] == "partial"
    assert case.get_run(outcome["run_id"])["analyzer"] == "firmware_emulation"
    command = next(call.args[0] for call in run_tool.call_args_list if "qemu-mipsel-static" in call.args[0])
    assert "--network" in command and "none" in command
    assert "qemu-mipsel-static" in command
    with pytest.raises(ValueError):
        engine.emulate(case, second.id, "../outside")


def test_emulation_without_container_records_needs_input(tmp_path: Path) -> None:
    case, evidence_id = _make_case(tmp_path)
    engine = FirmwareEngine()

    def extraction(_source: Path, root: Path, _mode: str, _warnings: list[str]) -> tuple[str, str]:
        root.mkdir(parents=True)
        (root / "etc").mkdir()
        (root / "lib").mkdir()
        (root / "service").write_bytes(_minimal_mips_elf())
        return "complete", ""

    with patch.object(engine, "_extract", side_effect=extraction):
        firmware = engine.analyze(case, evidence_id)
    with patch.object(engine, "_container_ready", return_value=(False, "container not started")):
        outcome = engine.emulate(case, firmware.id, "service")
    assert outcome["status"] == "needs_input"
    assert case.get_run(outcome["run_id"])["coverage"]["service_process_started"] is False


def test_partial_extraction_still_inventories_recovered_files_and_arm_emulation(tmp_path: Path) -> None:
    case, evidence_id = _make_case(tmp_path)
    engine = FirmwareEngine()

    def extraction(_source: Path, root: Path, _mode: str, _warnings: list[str]) -> tuple[str, str]:
        root.mkdir(parents=True)
        (root / "etc").mkdir()
        (root / "lib").mkdir()
        (root / "service").write_bytes(_minimal_arm_elf())
        return "partial", "Extractor returned an error after recovering one binary"

    with patch.object(engine, "_extract", side_effect=extraction):
        firmware = engine.analyze(case, evidence_id)
    assert firmware.status == "partial"
    assert firmware.coverage["extraction_completed"] is False
    assert firmware.coverage["regular_files"] == 1
    assert any(item.kind == "firmware.binary" and item.attributes["machine"] == "arm" for item in firmware.observations)
    with patch.object(engine, "_container_ready", return_value=(True, "")), patch("chainrecon.firmware_engine._result", return_value=subprocess.CompletedProcess(["docker"], 0, "service started", "")) as run_tool:
        outcome = engine.emulate(case, firmware.id, "service")
    assert outcome["status"] == "complete"
    command = next(call.args[0] for call in run_tool.call_args_list if "qemu-arm-static" in call.args[0])
    assert "qemu-arm-static" in command
    assert "/rootfs/service" in command


def test_container_mounts_only_selected_evidence_file(tmp_path: Path) -> None:
    case, evidence_id = _make_case(tmp_path)
    engine = FirmwareEngine()
    with patch.object(engine, "_container_ready", return_value=(True, "")), patch("chainrecon.firmware_engine._result", return_value=subprocess.CompletedProcess(["docker"], 1, "", "bad archive")) as run_tool:
        firmware = engine.analyze(case, evidence_id)
    assert firmware.status == "partial"
    command = next(call.args[0] for call in run_tool.call_args_list if "binwalk" in call.args[0])
    mounts = [command[index + 1] for index, value in enumerate(command[:-1]) if value == "--mount"]
    assert any(f"source={case.evidence_path(evidence_id)}" in mount and "target=/input/firmware" in mount for mount in mounts)
    assert not any("target=/input," in mount for mount in mounts)

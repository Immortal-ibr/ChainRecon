"""Extractor failures and inventory limits must be explicit in case coverage."""

import json
import os
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from chainrecon.case_model import Case
from chainrecon.elf_inspection import inspect_elf
from chainrecon.firmware_engine import FirmwareEngine, _network_indicator, identify_image


def _case(tmp_path: Path) -> tuple[Case, str]:
    image = tmp_path / "image.bin"
    image.write_bytes(b"unstructured firmware bytes")
    case = Case.create(tmp_path / "case")
    return case, case.add_evidence(image, kind="firmware").id


def test_oversized_text_certificate_and_total_budget_mark_partial(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    engine = FirmwareEngine()
    def extract(_source, root, _mode, _warnings):
        root.mkdir(parents=True)
        (root / "a.txt").write_bytes(b"a" * 8)
        (root / "b.txt").write_bytes(b"b" * 8)
        (root / "huge.txt").write_bytes(b"c" * 20)
        (root / "bad.crt").write_bytes(b"x" * 20)
        (root / "binary.bin").write_bytes(b"\x00" * 20)
        return "complete", ""
    with patch.object(engine, "_extract", side_effect=extract), patch("chainrecon.firmware_engine._MAX_TEXT_FILE", 16), patch("chainrecon.firmware_engine._MAX_TOTAL_TEXT", 10):
        run = engine.analyze(case, evidence_id)
    assert run.status == "partial"
    assert run.coverage["regular_files"] == 5
    assert run.coverage["text_files_read"] == 1
    assert run.coverage["text_files_skipped_limit"] == 2
    assert run.coverage["certificate_files_skipped_limit"] == 1
    assert any("budget" in warning for warning in run.warnings)
    assert any("huge.txt" in warning for warning in run.warnings)


def test_extracted_file_limit_marks_inventory_partial(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    engine = FirmwareEngine()
    def extract(_source, root, _mode, _warnings):
        root.mkdir(parents=True)
        (root / "one.txt").write_bytes(b"one")
        (root / "two.txt").write_bytes(b"two")
        return "complete", ""
    with patch.object(engine, "_extract", side_effect=extract), patch("chainrecon.firmware_engine._MAX_FILES", 1):
        run = engine.analyze(case, evidence_id)
    assert run.status == "partial"
    assert run.coverage["regular_files"] == 1
    assert any("File limit" in warning for warning in run.warnings)


@pytest.mark.parametrize("content,message", [
    ("[]", "advisories list"),
    ("{}", "advisories list"),
    ('{"advisories": ["broken"]}', "must be mappings"),
    ('{"advisories": [{"id": 1, "component": "x", "versions": []}]}', "string id"),
    ('{"advisories": [{"id": "A", "component": "x", "versions": [1]}]}', "exact version strings"),
])
def test_advisory_snapshot_is_validated_before_extraction(tmp_path: Path, content: str, message: str):
    case, evidence_id = _case(tmp_path)
    snapshot = tmp_path / "advisories.json"
    snapshot.write_text(content, encoding="utf-8")
    engine = FirmwareEngine()
    with patch.object(engine, "_extract", side_effect=AssertionError("extraction started")):
        with pytest.raises(ValueError, match=message):
            engine.analyze(case, evidence_id, advisory_snapshot=snapshot)
    assert case.manifest["runs"] == []


def test_advisory_snapshot_size_limit_precedes_extraction(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    snapshot = tmp_path / "oversized.json"
    with snapshot.open("wb") as handle:
        handle.seek(16 * 1024 * 1024)
        handle.write(b"x")
    engine = FirmwareEngine()
    with patch.object(engine, "_extract", side_effect=AssertionError("extraction started")):
        with pytest.raises(ValueError, match="16 MiB"):
            engine.analyze(case, evidence_id, advisory_snapshot=snapshot)
    assert case.manifest["runs"] == []


def test_extractor_reports_missing_tools_timeouts_and_empty_success(tmp_path: Path):
    source = tmp_path / "image.bin"
    source.write_bytes(b"data")
    engine = FirmwareEngine()
    root = tmp_path / "extracted"
    with patch("chainrecon.firmware_engine.shutil.which", return_value=None):
        status, reason = engine._extract(source, root, "trusted-host", [])
    assert status == "needs_input" and "Binwalk" in reason
    with pytest.raises(ValueError, match="Unknown extraction mode"):
        engine._extract(source, root, "unknown", [])
    with patch.object(engine, "_container_ready", return_value=(True, "")), patch("chainrecon.firmware_engine._result", side_effect=subprocess.TimeoutExpired("binwalk", 900)):
        status, reason = engine._extract(source, root, "container", [])
    assert status == "partial" and "did not complete" in reason
    with patch.object(engine, "_container_ready", return_value=(True, "")), patch("chainrecon.firmware_engine._result", return_value=subprocess.CompletedProcess([], 0, "", "")):
        status, reason = engine._extract(source, root, "container", [])
    assert status == "partial" and "without regular files" in reason
    (root / "recovered.bin").write_bytes(b"recovered")
    with patch("chainrecon.firmware_engine.shutil.which", return_value="/usr/bin/binwalk"), patch("chainrecon.firmware_engine._result", return_value=subprocess.CompletedProcess([], 0, "", "")):
        status, reason = engine._extract(source, root, "trusted-host", [])
    assert (status, reason) == ("complete", "")


def test_container_readiness_distinguishes_missing_cli_and_image(tmp_path: Path):
    engine = FirmwareEngine()
    with patch("chainrecon.firmware_engine.shutil.which", return_value=None):
        assert engine._container_ready()[0] is False
    with patch("chainrecon.firmware_engine.shutil.which", return_value="docker"), patch("chainrecon.firmware_engine._result", side_effect=OSError("daemon stopped")):
        assert "contact" in engine._container_ready()[1]
    with patch("chainrecon.firmware_engine.shutil.which", return_value="docker"), patch("chainrecon.firmware_engine._result", return_value=subprocess.CompletedProcess([], 1, "", "missing")):
        assert "image unavailable" in engine._container_ready()[1]
    with patch("chainrecon.firmware_engine.shutil.which", return_value="docker"), patch("chainrecon.firmware_engine._result", return_value=subprocess.CompletedProcess([], 0, "image", "")):
        assert engine._container_ready() == (True, "")


def test_identification_records_uimage_and_bounds_signature_output(tmp_path: Path):
    image = tmp_path / "many.bin"
    image.write_bytes(b"\x27\x05\x19\x56" + b"\x1f\x8b\x08" * 20)
    info = identify_image(image)
    assert any(item["type"] == "uimage" and item["offset"] == 0 for item in info["signatures"])
    assert info["signature_counts"]["gzip"] == 20
    assert info["signature_truncated"] is True
    assert len([item for item in info["signatures"] if item["type"] == "gzip"]) == 16


def test_network_indicator_keeps_only_target_and_rejects_invalid_port():
    assert _network_indicator(b"https://user:pass@camera.example.test:443/path?token=secret") == {"scheme": "https", "host": "camera.example.test", "port": 443}
    assert _network_indicator(b"https://example.test:bad/path") is None
    assert _network_indicator(b"https:///missing-host") is None


def test_diff_rejects_nonfirmware_run_and_forged_artifact_reference(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    engine = FirmwareEngine()
    def extract(_source, root, _mode, _warnings):
        root.mkdir(parents=True)
        (root / "version.txt").write_text("1", encoding="utf-8")
        return "complete", ""
    with patch.object(engine, "_extract", side_effect=extract):
        firmware = engine.analyze(case, evidence_id)
    run_path = case.root / "runs" / firmware.id / "run.json"
    original = run_path.read_text(encoding="utf-8")
    forged = json.loads(original)
    forged["artifacts"] = ["../outside.json"]
    run_path.write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid firmware inspection artifact"):
        engine.diff(case, firmware.id, firmware.id)
    run_path.write_text(original, encoding="utf-8")


def test_account_hash_schemes_and_startup_are_inventory_observations(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    engine = FirmwareEngine()
    def extract(_source, root, _mode, _warnings):
        (root / "etc/init.d").mkdir(parents=True)
        (root / "etc/shadow").write_text(
            "sha256:$5$salt$hash:0:0\nsha512:$6$salt$hash:0:0\nyescrypt:$y$salt$hash:0:0\nother:opaque:0:0\nmalformed\n",
            encoding="utf-8",
        )
        (root / "etc/init.d/boot").write_text("start", encoding="utf-8")
        return "complete", ""
    with patch.object(engine, "_extract", side_effect=extract):
        run = engine.analyze(case, evidence_id)
    schemes = {item.attributes["scheme"] for item in run.observations if item.kind == "firmware.password_hash_type"}
    assert schemes == {"sha256-crypt", "sha512-crypt", "yescrypt", "other"}
    assert any(item.kind == "firmware.startup" for item in run.observations)
    assert run.findings == ()


def test_emulation_rejects_wrong_root_and_architecture_and_records_runtime_failure(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    engine = FirmwareEngine()
    def extract(_source, root, _mode, _warnings):
        (root / "etc").mkdir(parents=True)
        (root / "lib").mkdir()
        elf = bytearray(52)
        elf[:6] = b"\x7fELF\x01\x01"
        struct.pack_into("<HH", elf, 16, 2, 3)
        (root / "service").write_bytes(elf)
        return "complete", ""
    with patch.object(engine, "_extract", side_effect=extract):
        firmware = engine.analyze(case, evidence_id)
    with pytest.raises(FileNotFoundError):
        engine.emulate(case, firmware.id, "missing")
    wrong_root = engine.emulate(case, firmware.id, "service", rootfs="etc")
    assert wrong_root["status"] == "needs_input"
    unsupported = engine.emulate(case, firmware.id, "service")
    assert unsupported["status"] == "needs_input"
    assert "supported ARM" in unsupported["reason"]
    service = case.root / "runs" / firmware.id / "extracted/service"
    data = bytearray(service.read_bytes())
    struct.pack_into("<H", data, 18, 8)
    service.write_bytes(data)
    with patch.object(engine, "_container_ready", return_value=(True, "")), patch("chainrecon.firmware_engine._result", side_effect=subprocess.TimeoutExpired("qemu", 1)):
        timeout = engine.emulate(case, firmware.id, "service", timeout=1)
    assert timeout["status"] == "partial"
    assert "TimeoutExpired" in timeout["reason"]
    with patch.object(engine, "_container_ready", return_value=(True, "")), patch("chainrecon.firmware_engine._result", return_value=subprocess.CompletedProcess([], 1, "", "error while loading shared libraries")):
        missing_loader = engine.emulate(case, firmware.id, "service")
    assert missing_loader["status"] == "partial"
    assert "Loader or shared library" in missing_loader["reason"]


def test_provenance_records_tool_identity_when_available(tmp_path: Path):
    engine = FirmwareEngine()
    with patch("chainrecon.firmware_engine._result", return_value=subprocess.CompletedProcess([], 0, "binwalk 2.4.3\n", "")):
        host = engine._tool_provenance("trusted-host")
        wsl = engine._tool_provenance("trusted-wsl")
        container = engine._tool_provenance("container")
    assert host["binwalk_version"] == "binwalk 2.4.3"
    assert wsl["binwalk_version"] == "binwalk 2.4.3"
    assert container["tools_image_id"] == "binwalk 2.4.3"
    with patch("chainrecon.firmware_engine._result", side_effect=OSError("missing executable")):
        assert "binwalk_version" not in engine._tool_provenance("trusted-host")


def test_elf_inspection_handles_64_bit_and_big_endian_headers(tmp_path: Path):
    elf64 = bytearray(128)
    elf64[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", elf64, 16, 2)
    struct.pack_into("<QQ", elf64, 32, 64, 0)
    struct.pack_into("<HHHH", elf64, 54, 56, 1, 64, 0)
    struct.pack_into("<IIQQQQQQ", elf64, 64, 0x6474E551, 1, 0, 0, 0, 0, 0, 0)
    path = tmp_path / "x86_64"
    path.write_bytes(elf64)
    assert inspect_elf(path) == {"interpreter": None, "needed": [], "pie": False, "nx_stack": False, "relro": "none", "parse_status": "complete"}
    big_endian = bytearray(52)
    big_endian[:6] = b"\x7fELF\x01\x02"
    struct.pack_into(">HH", big_endian, 16, 2, 8)
    path.write_bytes(big_endian)
    assert inspect_elf(path)["parse_status"] == "complete"


def test_trusted_wsl_extraction_reports_path_translation_failure(tmp_path: Path):
    source = tmp_path / "image.bin"
    source.write_bytes(b"bytes")
    engine = FirmwareEngine()
    with patch("chainrecon.firmware_engine.os", SimpleNamespace(name="nt", walk=os.walk)), patch("chainrecon.firmware_engine.shutil.which", return_value="wsl"), patch("chainrecon.firmware_engine._result", side_effect=[
        subprocess.CompletedProcess([], 1, "", "bad source"),
        subprocess.CompletedProcess([], 0, "/mnt/output\n", ""),
    ]):
        status, reason = engine._extract(source, tmp_path / "out", "trusted-wsl", [])
    assert status == "needs_input"
    assert "translate" in reason


def test_trusted_wsl_extraction_uses_translated_paths(tmp_path: Path):
    source = tmp_path / "image.bin"
    source.write_bytes(b"bytes")
    engine = FirmwareEngine()
    root = tmp_path / "out"
    def run_tool(command, *, timeout):
        if "wslpath" in command:
            return subprocess.CompletedProcess(command, 0, "/mnt/translated\n", "")
        (root / "recovered.txt").write_text("recovered", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")
    with patch("chainrecon.firmware_engine.os", SimpleNamespace(name="nt", walk=os.walk)), patch("chainrecon.firmware_engine.shutil.which", return_value="wsl"), patch("chainrecon.firmware_engine._result", side_effect=run_tool):
        assert engine._extract(source, root, "trusted-wsl", []) == ("complete", "")


def test_elf_parser_marks_untrusted_dynamic_tables_partial(tmp_path: Path):
    data = bytearray(256)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 16, 2)
    struct.pack_into("<QQ", data, 32, 0, 64)
    struct.pack_into("<HHHH", data, 54, 56, 0, 64, 2)
    # A dynamic section linked to a string table. Both are kept inside a
    # bounded synthetic file so malformed offsets can be tested safely.
    struct.pack_into("<IIQQQQIIQQ", data, 64, 0, 6, 0, 0, 192, 16, 1, 0, 0, 16)
    struct.pack_into("<IIQQQQIIQQ", data, 128, 0, 3, 0, 0, 240, 8, 0, 0, 0, 0)
    path = tmp_path / "dynamic.elf"
    for section_offset, section_length, entry_size in ((300, 8, 16), (240, 8, 8)):
        variant = bytearray(data)
        struct.pack_into("<QQ", variant, 128 + 24, section_offset, section_length)
        struct.pack_into("<Q", variant, 64 + 56, entry_size)
        path.write_bytes(variant)
        assert inspect_elf(path)["parse_status"] == "partial"

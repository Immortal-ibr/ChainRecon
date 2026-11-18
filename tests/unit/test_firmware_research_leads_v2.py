"""Static firmware leads must link to specific source and configuration evidence."""

from pathlib import Path
import struct
from unittest.mock import patch

from chainrecon.case_model import Case
from chainrecon.firmware_engine import FirmwareEngine, _lua_http_shell_flows


def test_luci_form_to_shell_rule_avoids_quoted_and_reassigned_values() -> None:
    source = b'''local http = require("luci.http")
function bad()
  local cmd = http.formvalue("cmd")
  io.popen(tostring(cmd).." 2>&1")
end
function safe()
  local cmd = http.formvalue("cmd")
  cmd = "fixed"
  io.popen(cmd)
end
function quoted()
  local cmd = http.formvalue("cmd")
  os.execute(shellquote(cmd))
end
'''
    assert _lua_http_shell_flows(source) == [{"parameter": "cmd", "sink": "io.popen", "source_line": 3, "line": 4, "function": "bad", "route": ""}]
    unrelated_sink = b'''local http = require("luci.http")
function webcmd()
 local cmd = http.formvalue("cmd")
 os.execute("fixed")
 io.popen(cmd)
end
'''
    assert _lua_http_shell_flows(unrelated_sink) == [
        {"parameter": "cmd", "sink": "io.popen", "source_line": 3, "line": 5, "function": "webcmd", "route": ""}
    ]


def test_firmware_run_links_luci_flow_and_ssh_policy_to_files(tmp_path: Path) -> None:
    image = tmp_path / "image.bin"
    image.write_bytes(b"firmware fixture")
    case = Case.create(tmp_path / "case")
    evidence = case.add_evidence(image, kind="firmware")

    def extract(_source, root, _mode, _warnings):
        fs = root / "squashfs-root"
        (fs / "etc/config").mkdir(parents=True)
        (fs / "usr/lib/lua/luci/controller/sample").mkdir(parents=True)
        (fs / "usr/bin").mkdir(parents=True)
        (fs / "etc/shadow").write_text("root:$1$salt$hash:0:0\n", encoding="utf-8")
        (fs / "etc/rc.local").write_text("/usr/bin/shellback &\ntelnetd -p 65534 &\nexit 0\n", encoding="utf-8")
        binary = bytearray(64)
        binary[:6] = b"\x7fELF\x01\x01"
        struct.pack_into("<HH", binary, 16, 2, 40)
        binary.extend(b"socket\x00bind\x00listen\x00accept\x00execve\x00/bin/sh\x00")
        (fs / "usr/bin/shellback").write_bytes(binary)
        (fs / "etc/config/dropbear").write_text("config dropbear\n option PasswordAuth 'on'\n option RootPasswordAuth 'on'\n", encoding="utf-8")
        (fs / "etc/config/application").write_text(
            "password=example-static-value\npassword=$from_environment\nsecret=true\n", encoding="utf-8"
        )
        (fs / "usr/lib/lua/luci/controller/sample/fields.lua").write_text("password = user_input\ntoken = formvalue('token')\n", encoding="utf-8")
        (fs / "usr/lib/lua/luci/controller/sample/sample.lua").write_text(
            'local http = require("luci.http")\nfunction index()\n entry({"admin", "sample", "webcmd"}, call("webcmd"))\nend\nfunction webcmd()\n local cmd = http.formvalue("cmd")\n io.popen(tostring(cmd))\nend\n', encoding="utf-8")
        return "complete", ""

    engine = FirmwareEngine()
    with patch.object(engine, "_extract", side_effect=extract):
        run = engine.analyze(case, evidence.id)
    assert run.status == "complete"
    assert len(run.findings) == 4
    observations = {item.id: item for item in run.observations}
    shell = next(item for item in run.findings if "shell execution" in item.title)
    linked = [observations[oid] for oid in shell.observation_ids]
    assert linked[0].locator.endswith("sample.lua:line:7")
    assert linked[0].attributes["parameter"] == "cmd"
    assert linked[0].attributes["source_line"] == 6
    assert linked[0].attributes["route"] == "/admin/sample/webcmd"
    ssh = next(item for item in run.findings if "Root SSH" in item.title)
    assert {observations[oid].kind for oid in ssh.observation_ids} == {"firmware.password_hash_type", "firmware.service_option"}
    telnet = next(item for item in run.findings if "Telnet" in item.title)
    assert observations[telnet.observation_ids[0]].attributes["port"] == 65534
    custom = next(item for item in run.findings if "custom program" in item.title)
    assert {observations[oid].kind for oid in custom.observation_ids} == {"firmware.startup_command", "firmware.network_shell_binary"}
    assert all(item.status == "candidate" for item in run.findings)
    credential_leads = [item for item in run.observations if item.kind == "firmware.credential_string"]
    assert [item.locator for item in credential_leads] == ["squashfs-root/etc/config/application:line:1"]

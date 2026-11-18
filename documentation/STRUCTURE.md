# Repository structure

| Path | Role |
| --- | --- |
| `chainrecon/case_model.py` | Portable evidence, runs, review history, SQLite query index, v1 result importer |
| `chainrecon/case_analysis.py` | Offline scan, traffic, APK, Frida log, and workflow case adapters |
| `chainrecon/firmware_engine.py` | Image identification, isolated extraction, filesystem inventory, diff, guided emulation |
| `chainrecon/elf_inspection.py` | Bounded ELF loader, dependency, and hardening inspection |
| `chainrecon/runners/workflow_runner.py` | Typed declarative workflow execution and resume |
| `chainrecon/runners/frida_runner.py`, `frida_catalog.py`, `frida_session.py`, `chainrecon/frida_events.py` | Frida orchestration, built-in scripts, session state, and structured redacted events |
| `chainrecon/analysis/`, `chainrecon/analysis_catalog.py` | Offline analyzers, compatibility formats, and evidence-to-analyzer policy |
| `chainrecon/plugins/` | JSON, HTML, CSV, and XLSX exports |
| `chainrecon/tui/` | Textual client with separate investigation, analysis, and standalone packet screens |
| `chainrecon/resources/` | Defaults, generic profile, network scripts, example workflow, and example plugin shipped in the wheel |
| `chainrecon/v2_cli.py` | Case-first CLI commands |
| `chainrecon/__init__.py` | Existing CLI commands and compatibility aliases |
| `docker/firmware-tools.Dockerfile` | Local isolated Binwalk and QEMU tool image |
| `scripts/check_coverage.py`, `scripts/check_dist.py`, `scripts/smoke_install.py`, `scripts/validate_firmware.py` | Release gates and reproducible local firmware validation |
| `tests/` | Offline unit, integration, requirement, and TUI tests |

`config/` and `profiles/devices/` in the checkout are development examples. Runtime personal configuration is stored under the user's application-data directory. The default profile does not contain a target address. Cases and extracted firmware should be created outside the repository.

The `legacy/` directory contains historical scripts, some of which are not active entry points. The `interactive` CLI alias opens the TUI; its obsolete text menu has been removed. The TUI starts analysis from named firmware, packet, APK, Nmap XML, and Frida-log entries, all backed by the same investigation folder. Reports is a visible home entry. The broken Python-native scanner option has been removed from the scan TUI; Nmap XML is its scan evidence.

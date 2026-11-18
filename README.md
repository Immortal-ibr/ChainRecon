# ChainRecon

ChainRecon 2.0 is a local IoT investigation toolkit. It stores raw evidence and derived analyses in portable case folders so an analyst can trace each finding back to a file, offset, packet, or tool output. Network scans and external enrichment require an explicit command; offline analysis does not contact the target or advisory services.

## Install

Python 3.11–3.13 is supported. From a checkout:

```shell
python -m pip install -e ".[tui]"
python -m chainrecon --help
```

The core package includes Nmap XML parsing, packet analysis, APK inspection, report export, firmware identification, and case management. Nmap, TShark, Binwalk, Docker, QEMU, Frida, JADX, and Android tools are separate executables needed only for their respective tasks. The wheel includes default configuration, the generic device profile, built-in Frida scripts, network setup scripts, and the example community plugin. Personal settings live in `%APPDATA%\ChainRecon` on Windows and the XDG configuration directory on Linux.

## Start a case

```shell
chainrecon case init ./cases/lab-001 --title "Camera firmware review"
chainrecon case add ./cases/lab-001 ./firmware.bin --kind firmware
chainrecon case add ./cases/lab-001 ./boot.log --kind uart_log
chainrecon case list ./cases/lab-001 evidence
chainrecon case verify ./cases/lab-001
```

Evidence is copied to `evidence/sha256/<digest>`. The manifest uses relative paths; moving the entire folder preserves references. The SQLite index is disposable and can be rebuilt with `case reindex`. Case data, including raw evidence, can contain secrets. Keep case folders in a controlled local location.

Each analysis records a `complete`, `partial`, `failed`, or `needs_input` status, warnings, coverage, observations, candidate findings, and tool provenance. A skipped check or missing packet is not evidence that an issue is absent. Review a candidate before disclosure:

```shell
chainrecon case list ./cases/lab-001 findings
chainrecon case review ./cases/lab-001 finding-ID confirmed --reviewer analyst --note "Reproduced on firmware build X"
chainrecon report export ./cases/lab-001 --format html --output ./cases/lab-001/report.html
```

`case import-v1` imports an old JSON result as unverified observations and candidate findings. It does not rerun the old analysis.

To work repeatedly on one case, set `case.directory` in the per-user `local.yaml`
or in a project YAML selected with `CHAINRECON_CONFIG_FILE`. For example:

```yaml
case:
  directory: 'C:\cases\camera-lab'
firmware:
  mode: container
```

`chainrecon tui` opens the home. An **investigation** is one folder containing
copied source files, analysis runs, finding reviews, and reports. The Python API,
CLI, and configuration still call this a **case**; the TUI uses *investigation*
consistently. Passing `chainrecon tui CASE_PATH` opens that folder directly.

| Task | TUI path |
| --- | --- |
| Create or switch the investigation folder | **Switch investigation** on the home |
| Import a firmware image, capture, APK, scan XML, or log | **Files & findings → Import file** |
| Analyze an imported file | Choose **Firmware / flash**, **Packet captures**, **Android APK**, **Nmap XML**, or **Frida logs** on the home |
| Review candidate findings | **Files & findings → Review findings** |
| Export a report | **Reports** on the home; the current investigation is selected by default |

Each analysis screen lists only imported files of its type. If none exists,
**Add or manage files** takes you to the import screen. Packet capture and APK
analysis also link to their optional standalone tools. Those tools save separate
results; use the named analysis screen for a run recorded in the investigation.
The Reports screen can instead use this TUI session or saved standalone results
when explicitly selected.

The configured `case.directory` supplies the default investigation folder.
CLI commands such as `chainrecon case add IMAGE --kind firmware`, `case analyze`,
and `report export` use that folder unless an explicit path is given. CLI analysis
selects a compatible imported file automatically when exactly one exists; use an
evidence ID when multiple files match. Workflows record in the configured folder
unless they are plans or dry runs. In the TUI, `Ctrl+O` switches folders and
`Ctrl+N` creates one in the folder picker. Tab completes file and directory paths;
`Ctrl+Tab` moves to the next field. On Windows, set `CHAINRECON_ASCII_UI=1` only
for terminals that cannot render box-drawing characters.

The bottom bar keeps `F1 Help` visible at the right edge; press `F1` or click it
for navigation and the current screen's shortcuts. When a path field is focused,
the bar also shows `Tab Complete path` and `Ctrl+Tab Next field`. The case picker
shows its path and folder browsing keys.

## Firmware

The default extractor executes Binwalk in the `chainrecon/firmware-tools:2.0` container with no network, no added capabilities, a read-only root filesystem, CPU/memory/process limits, and read-only input. Build the local image once:

```shell
docker build -f docker/firmware-tools.Dockerfile -t chainrecon/firmware-tools:2.0 .
chainrecon firmware analyze ./cases/lab-001 ev-SHA256
```

Docker Desktop or a compatible engine must be running. On a trusted image, Windows users with Binwalk in WSL can instead select `--mode trusted-wsl`; Linux users with a host Binwalk installation can select `--mode trusted-host`. These two modes execute the extractor outside the container and require explicit selection. If the tool environment is unavailable, the run reports `needs_input`.

The analyzer identifies image signatures and MBR partitions before extraction, records offsets, and inventories regular files without following symlinks. It hashes extracted files and records startup files, services, account databases and password hash schemes, X.509 certificates, network URI targets, package versions, and ELF architecture, loader, dependencies, and hardening metadata. URI observations omit credentials, paths, and query strings; the raw evidence remains available in the case. A private key, credential-like string, version match, or weak hash is a review candidate; the analyzer does not claim exploitability from presence alone. Firmware observations carry relevant [OWASP ISTG firmware test area](https://github.com/OWASP/owasp-istg/blob/main/src/03_test_cases/firmware/README.md) identifiers.

```shell
chainrecon firmware diff ./cases/lab-001 run-before run-after
chainrecon firmware emulate ./cases/lab-001 run-ID INVENTORY_PATH_TO_SERVICE --timeout 20
```

Use the service's `path` in `runs/RUN_ID/inspection.json` as `INVENTORY_PATH_TO_SERVICE`. The analyzer infers a root filesystem containing `etc` and `lib`; pass `--rootfs` with its extraction-relative path if inference fails. Guided emulation runs a selected ARM, AArch64, or MIPS Linux ELF with QEMU user mode in the isolated container. It captures stdout, stderr, and exit status. It is a service-level experiment, not a full device boot. Optional `--advisory-snapshot snapshot.json` performs exact package-version matching against a researcher-supplied local JSON snapshot; no online advisory lookup is performed automatically.

## Other evidence

```shell
chainrecon case add ./cases/lab-001 ./scan.xml --kind scan_xml
chainrecon case analyze ./cases/lab-001 ev-SHA256
chainrecon case analyze ./cases/lab-001 ev-SHA256 --analyzer traffic
chainrecon case analyze ./cases/lab-001 ev-SHA256 --analyzer apk
chainrecon case analyze ./cases/lab-001 ev-SHA256 --analyzer frida_log
chainrecon analyze-ssl 192.0.2.10 --ports 443 8443
```

Nmap XML is the authoritative scan format. A service name or `open|filtered` UDP state is recorded as an observation, not a CVE match or vulnerability finding. `analyze-ssl` makes an explicit live TLS probe; the case analysis commands above read existing evidence offline. Primary packet analysis streams captures with bounded retained results; TShark/PyShark supports PCAP and PCAPNG when installed, and Scapy handles PCAP as a fallback. Specialist packet-list analyzers stop at 10,000 packets and mark their result `partial` when the capture continues. APK permissions, ports, protocol labels, missing handshake packets, and source keywords are treated as leads, not automatic vulnerabilities. Frida output is structured and redacted by default; explicitly enabling sensitive output keeps that material in local artifacts.

## Workflows and TUI

```shell
chainrecon workflow plan workflows/example.yaml --target 192.0.2.10
chainrecon workflow run workflows/example.yaml --case ./cases/lab-001
chainrecon workflow resume workflows/example.yaml --case ./cases/lab-001 --resume-file PATH_FROM_RUN_OUTPUT --approve-step review-id
chainrecon tui ./cases/lab-001
```

Workflow conditions support literals, Boolean operators, comparisons, `in`, and dotted access to declared data. Function calls, indexing, and private attributes are rejected during preflight, including in branches that will be skipped. Pipelines can declare typed inputs (`string`, `integer`, `number`, `boolean`, `path`); supply them with `--input NAME=VALUE`. Dry runs create no case artifacts. Executable community steps require `trusted: true` in the pipeline. A review step pauses execution until resumed with `--approve-step`. Workflow summaries are atomically checkpointed after each step; resume files are tied to the pipeline SHA-256, typed inputs, target, profile, and their artifact directory. Case-backed checkpoint paths are relative to the case folder and can be resumed after moving it. `workflow run --case` copies the pipeline into the case and records the result; pass `--evidence-id` for other inputs already imported into that case. A `firmware` step accepts `evidence_id` in a case workflow or an image path, and uses the isolated firmware engine. A critical firmware step that returns `partial` or `needs_input` stops the workflow with that status.

The home groups named analysis types, Reports, and live device work. The investigation screen manages imported files and finding reviews; Reports handles exports. Each analysis screen shows run history and coverage for its selected file. Firmware extraction settings appear only for firmware and flash dumps. UART logs, Frida summaries, and other files can be attached for manual review. Scan keeps target and profile up front; Frida puts optional script parameters and device setup below the main Run action. Settings shows configuration paths and tool availability without displaying secret values.

When a case is open, the scan, capture, and Frida screens also copy their raw outputs into it and record linked analysis runs. Community plugin validation checks manifests and entrypoint files without importing Python code; running one requires explicit trust in the TUI or `trusted: true` in a workflow. Legacy scan, capture, APK, workflow, report, and TUI commands remain as compatibility paths. The legacy `firmware IMAGE --extract-dir CASE_FOLDER` command now creates or reuses a case and uses the isolated firmware engine. The `interactive` command opens the case TUI; the old menu and broken Python-native scanner option have been removed.

## Testing and release state

```shell
python -m pip install -e ".[dev,tui]"
python -m pytest tests
python -m ruff check chainrecon tests scripts --select E4,E7,E9,F
python scripts/build_clean.py --outdir dist
python scripts/check_dist.py
python scripts/smoke_install.py 'dist/chainrecon-2.0.0-*.whl'
python scripts/smoke_install.py 'dist/chainrecon-2.0.0.tar.gz'
```

CI is configured to run the full offline suite on Windows and Linux with Python 3.11, 3.12, and 3.13. A separate wheel smoke check installs into a clean virtual environment, verifies bundled resources, imports the TUI, and exercises CLI help. The release gate requires 80% overall line coverage and 90% branch coverage in case, firmware, and workflow code. Local validation results and remaining limits are in [testing.md](documentation/testing.md), the [framework review](documentation/framework-review-2026-11-18.md), and the [release checklist](RELEASE_CHECKLIST.md). There is no public scheduled live-device job; live checks are a separate local procedure. No case data is uploaded by CI.

See [design.md](documentation/design.md) for the data model and trust boundaries, [STRUCTURE.md](documentation/STRUCTURE.md) for the code map, and [history-cleanup.md](documentation/history-cleanup.md) before any separately authorized online history change.

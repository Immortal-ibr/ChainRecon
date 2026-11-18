# Framework review — 18 November 2026

This review followed the case API, CLI, TUI routes, offline analyzers, firmware engine, live scan/capture/Frida recording, workflows, reporting, packaging, CI configuration, and related tests. It used local code and fixtures. It did not execute hosted CI, probe a device, or analyze Tapo C210 firmware.

## Evidence and analysis contract

| Imported type | Built-in case analysis | Notes |
| --- | --- | --- |
| Firmware image, flash dump | Firmware identification and extraction | Extraction environment is selected in Analysis; isolated container is the default. |
| Nmap XML | Scan parsing | Service-name hints and ambiguous UDP states remain observations, not CVE findings. |
| PCAP/PCAPNG | Traffic analysis | Backend availability and capture coverage are reported by the run. |
| Android APK | Static APK analysis | Requires JADX; decode errors or a missing manifest make the run partial. |
| Frida log | Event parsing | Sensitive content is redacted in the normalized result. |
| UART log, Frida summary, other file | None | Stored as hashed evidence for manual review. |
| Imported version 1 result | No reanalysis | `case import-v1` records its old claims as unverified candidates. |

The catalog in `chainrecon/analysis_catalog.py` is the shared source for these rules. The case service and firmware engine reject incompatible evidence before creating a run. `case analyze` selects the analyzer automatically for a compatible input. The TUI presents analysis separately from evidence import, finding review, and report export. Its Analysis screen shows the selected type, available analyzer, all prior runs linked to the file (including workflow and legacy imports), status, coverage, warnings, and finding locations. Evidence import accepts regular files; it does not import directories as one evidence item.

## Review by subsystem

| Area | Verified behavior | Material limit |
| --- | --- | --- |
| Case model and CLI | Imported bytes are copied, hashed, and checked before analysis; case commands can use a configured default folder. Analyzer/type mismatches fail before a run is made. | File permissions do not make case files tamper-proof. Hash verification detects changed raw evidence; the manifest and run documents are not cryptographically signed. |
| TUI | The home names firmware, packet, APK, Nmap XML, and Frida-log analysis, plus Reports. Each analysis screen filters the current investigation's files by type and shows run history. The investigation screen manages files and review; Reports defaults to that investigation. The footer shows F1 help and path-specific Tab actions. Keyboard navigation and 80×24 layout have tests. | Specialist toolkit outputs still live outside an investigation run. |
| Firmware | Identification, bounded extraction/inventory, advisory candidates, diff, and guided service emulation have offline fixtures and prior local IoTGoat/OpenWrt runs. | No C210 firmware or physical-board validation. A firmware signature or advisory match does not prove a reachable flaw. |
| Scan and traffic | Nmap XML is the case scan input; PCAP analysis retains bounded results and reports coverage. Service labels and ambiguous UDP states stay observations. | Nmap completion metadata and raw XML/packet locators need stronger recording. |
| APK and Frida | APK decode failures are visible as partial runs; the JADX deadline is enforced. Frida-log case results are redacted. | APK heuristics and recorded Frida events need researcher confirmation; live instrumentation was not rerun here. |
| Workflows | Declarative condition parsing, typed inputs, review steps, resume integrity, and error propagation have offline tests. | Executable plugins and live workflow steps still require explicit local trust and target authorization. |
| Reports and delivery | HTML/spreadsheet injection regressions, clean source/wheel build, wheel import, lint, typing, and CI configuration are covered. The full offline suite passed on local Windows 3.11–3.13 and Linux 3.11. | Hosted CI and Linux 3.12/3.13 after this UI change remain separate release work. |

## Findings addressed in this review

1. **Conflicting UI routes.** The old case page mixed evidence import with an analysis button and firmware settings, while the old Analysis page accepted only PCAP. The home now has type-specific analysis routes backed by one investigation folder. The old packet tools are labeled as standalone specialist tools.
2. **Analyzer mismatch.** Direct library and CLI calls could run an analyzer against the wrong evidence classification. Compatibility is now checked before a run directory is created.
3. **Silent type conflict.** Importing identical bytes with a different type previously returned the first classification. It now reports the conflict; repeat import with the same type remains idempotent.
4. **Misleading scan claims.** Service names and `open|filtered` UDP states were shown as risk/CVE candidates. They are now observations for researcher review. A version or exploitability claim requires separate evidence.
5. **Generic and nonportable derived output.** Common scan, traffic, and APK observations now name the actual host, domain, service, component, or permission when available. Derived analyzer metadata points to case-relative paths rather than the original machine path.
6. **Incomplete APK status and stalled JADX.** Decode errors, a warning exit, or a missing decoded manifest mark the case run `partial`. The JADX output reader now drains concurrently with a process deadline, so a stalled process can be killed.
7. **Coverage gate path collision.** A TUI file with the same basename as the core case module made the release gate count the wrong files. The gate now matches full module paths and has a regression test.
8. **Run history omission.** Filtering history by the currently selected analyzer hid workflow and imported runs tied to a source. History now follows evidence IDs and labels each analyzer.
9. **False successful scan.** A non-Nmap XML document containing `<nmaprun` in a comment could pass the preflight and return a complete empty scan. The parser now validates the XML root element. Service hints are worded as checks to perform, without claiming an exposed administrative service or a CVE.
10. **Undiscoverable keyboard controls.** Help existed behind `?`, which a new user had no reason to know. The bottom bar now shows `F1 Help`; focused path fields show `Tab Complete path` and `Ctrl+Tab Next field`. F1 opens navigation basics and the current screen's shortcuts, including in the case picker. The picker retains its own visible hints.
11. **Hidden analysis routes and stale script execution.** Packet and APK analysis were inside a collapsed More tools section. The home now names both as analysis types; their screens link to the specialist standalone tools. Packet and APK file paths use Tab completion. Their custom scripts run only when the custom option is selected; a stale hidden script path cannot trigger one. Visible specialist logs escape untrusted markup and redact obvious credential values.
12. **Case, analysis, and reports ambiguity.** The TUI mixed “case” with “investigation,” gave firmware a generic “Analyze case evidence” entry, and hid Reports under More tools. It now uses “investigation” for the saved folder, names each analysis entry by its file type, filters the file picker accordingly, and exposes Reports on the home. Reports defaults to the active investigation; session and saved standalone results require a source choice.

## Remaining limits and review priorities

- Generic scan, packet, APK, and Frida adapters link observations to a path inside their derived `analysis.json`. They do not yet provide packet numbers, XML node locations, or source-code line locations for every observation. A reviewer must trace a claim back to the copied raw evidence before confirmation. Improving these raw locators is the next evidence-quality task.
- The specialist standalone packet and APK tools still write separate artifacts. For reproducible investigation work, import the source and use the corresponding named analysis route. Automatic promotion of standalone artifacts into an investigation is not implemented.
- UART logs and Frida summaries are attachable evidence with no built-in analyzer. The interface states this explicitly; a manual review or trusted extension remains necessary.
- Nmap host and service observations currently point to derived JSON rather than XML nodes, and the parser does not yet record Nmap's scan-completion metadata. A parsed scan does not establish that the target inventory is complete.
- The investigation screen's finding selector lists up to 1,000 indexed findings. Large cases need pagination and an explicit total count to avoid conflating listed results with case totals.
- Firmware advisory matching uses an explicit local snapshot and exact package versions. It is not an online CVE search or proof that a device is vulnerable. The local IoTGoat and OpenWrt validation in `documentation/testing.md` does not establish anything about a C210 image.
- Hosted CI and a physical-device run remain unverified. The package version is prepared as `2.0.0` for a release branch; the tag and public release remain pending. Exact suite counts and coverage are in `documentation/testing.md`.

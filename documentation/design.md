# Design: case-first investigations

ChainRecon 2.0 is in development. The Python API is the source of truth; the CLI and TUI call it. A case folder is a movable directory with a versioned `case.json`, content-addressed raw evidence, append-only run documents, manifest snapshots, review history, derived artifacts, and a rebuildable SQLite index. Absolute source-machine paths are not stored in the case manifest. `case verify` rehashes raw evidence. The index is a query cache, not evidence.

## Record model

`EvidenceRef` identifies a copied raw file by SHA-256. `Observation` describes one verifiable fact with an evidence ID and locator. `Finding` references observations and starts as `candidate`; the researcher can confirm or reject it with a recorded decision. `RunRecord` stores the input evidence IDs, analyzer, status, times, tool versions, settings, warnings, coverage, observations, findings, and derived artifact paths. The four statuses are `complete`, `partial`, `failed`, and `needs_input`.

Case writes check the manifest revision before saving, so a stale reader receives a conflict instead of silently replacing another writer's work. This is optimistic conflict detection, not multiwriter transaction support; reopen the case and retry after a conflict.

The model intentionally separates a signature, package version, credential-like string, account database, or protocol label from a confirmed vulnerability. Missing data is represented in coverage and warnings. A finding should include affected component/version, reproduction, impact, remediation, and references before disclosure.

## Firmware trust boundary

Identification reads bounded signatures and MBR metadata before extraction. The default Binwalk path runs in a locally built OCI image with no network, a read-only root filesystem, dropped capabilities, and resource limits. The input is mounted read-only and the output in a dedicated run directory. A researcher may explicitly choose trusted WSL or host execution. The inventory walks regular files without following symlinks, hashes each file, caps file and text inspection, and reports any incomplete coverage. The ELF parser reads bounded headers and tables; it does not execute binaries. Guided emulation selects one Linux ELF and a matching extracted root filesystem and invokes QEMU user mode in the isolated environment. It does not emulate the full device.

Current firmware observations map to [OWASP ISTG firmware areas](https://github.com/OWASP/owasp-istg/blob/main/src/03_test_cases/firmware/README.md): information gathering, configuration and patch management, secrets, and cryptography. A local advisory snapshot can match an exact package version. A match remains a candidate until configuration, reachability, and exploitability are reviewed. External enrichment is not automatic.

## Other analyzers

The scan parser treats Nmap XML as authoritative. The primary packet path streams with bounded retained results and reports DNS answers, IPv6 endpoints, TCP flows, TLS metadata, MQTT events, and media indicators when observable. Specialist analyzers use a streaming reader with a 10,000-packet batch limit; truncation is recorded and stops a critical workflow step as partial. It does not infer secure transport from port 8883 or infer anonymous access from a missing MQTT CONNECT packet. A self-issued certificate name is not counted as a verified self-signature; certificate observations require client-behavior review before a vulnerability claim. APK inspection records permissions and components as leads; absence of a pinning heuristic is inconclusive. Frida session output is structured and redacted by default.

The evidence-to-analyzer catalog is shared by the case API, CLI, and TUI. An analyzer must accept the imported evidence type before a run directory is created. The TUI calls a case folder an investigation. Its home names the supported analysis types, and each analysis screen filters the imported-file list to that type. The investigation screen handles import and finding review; Reports is a separate visible entry and defaults to the active investigation. Firmware extraction settings appear only for firmware. UART logs, Frida summaries, and other attachments are explicitly marked for manual review. Specialist packet and APK tools remain available from their type-specific screens for exploratory work outside an investigation run.

## Workflows

YAML steps have unique IDs and supported types. Conditions are parsed into a data-only subset with Boolean operators, comparisons, membership, and dotted lookups. Function calls, indexing, and private attributes are rejected across the entire syntax tree. Inputs can be typed. Dry runs render without creating artifacts. A review step pauses execution; each non-dry step is atomically checkpointed, and resume requires the same pipeline SHA-256, execution context hash, and artifact directory. Interrupted steps rerun while completed steps are preserved. Executable community plugins require `trusted: true`. A case-bound workflow copies the pipeline as evidence, records relative artifact paths, and can resume after the case folder moves. Firmware steps use the case firmware engine and link to imported firmware evidence. Other input evidence must be imported and named explicitly.

## Privacy and exports

Raw evidence is intentionally preserved. Derived exports redact recognized secrets and local home paths, escape HTML, and prefix spreadsheet formula-looking text. These safeguards reduce accidental disclosure; the analyst still reviews a report before sharing. Public CI never runs against a device or uploads lab artifacts. Personal settings and device profiles belong in user application-data directories.

## Release gates

The offline suite, lint, focused type checking, dependency audit, source and wheel installation checks, and CLI/TUI smoke tests run in CI. The release coverage targets are 80% overall line coverage and 90% branch coverage for case, firmware, and workflow code. Hardware validation remains a separately invoked local procedure.

# Local validation and release status

ChainRecon 2.0.0 is prepared locally for a release branch. The tag, GitHub release, hosted CI, and online history cleanup remain pending. Earlier sections below record development-stage results; the latest release checks are at the end.

## 2.0.0 release preparation (2026-11-18)

The full offline suite collected 762 tests. Windows Python 3.12.4 and local Linux Docker Python 3.11.18 each passed 761 tests and skipped one live Frida emulator test. Eight previously hidden, mocked Frida command tests now run offline; their assertions were updated for rendered scripts and default output redaction. A missing device serial in the device-wide class census now fails explicitly instead of reaching Frida as `None`.

The Windows branch-coverage run passed the release gates: 81.7% overall line coverage, 94.2% case branch coverage, 90.1% firmware branch coverage, and 92.0% workflow branch coverage. Ruff's CI selection, scoped mypy across 20 files, `pip check`, `pip-audit . --strict`, and `git diff --check` passed locally. A clean isolated build produced `chainrecon-2.0.0` wheel and source archives; Twine metadata checks passed. Both artifacts installed into separate clean environments and exercised the installed console command, module CLI, case workflow, bundled assets, and TUI on Windows Python 3.12 and Linux Python 3.11.

Hosted GitHub Actions remains the final gate for the Windows/Linux Python 3.11–3.13 matrix and dependency/package jobs. The release tag must wait for that result. The live Frida test needs an authorized Android emulator and server and is not an offline packaging gate. The current tree removes prior device-specific files, while old public commits still retain them.

## Offline and package checks

| Environment | Offline suite | Notes |
| --- | ---: | --- |
| Windows 11, Python 3.11.18 | 712 passed, 9 skipped | Isolated local installation; full offline suite with branch coverage. |
| Windows 11, Python 3.12.4 | 712 passed, 9 skipped | Full offline suite with branch coverage; optional live Frida checks skipped. |
| Windows 11, Python 3.13 | 712 passed, 9 skipped | Isolated source install with TUI and development extras. |
| Linux (local Docker), Python 3.11.18 | 712 passed, 9 skipped | Full offline suite with branch coverage in a disposable container. |
| Linux (Kali under WSL), Python 3.13.9 | 712 passed, 9 skipped | Full offline suite with branch coverage; optional live Frida checks skipped. |

The Windows and Linux runs exercised all tests collected by `pytest tests`, including the 71 tests omitted by the former CI command. A local Python 3.11.18 installation also passed `pip check`, Ruff's `E4,E7,E9,F` check, the focused mypy check of the case, firmware, workflow, CLI, and redaction modules, and the CLI smoke check. `pip-audit . --strict` found no known vulnerabilities in declared dependencies at the time of testing. These checks do not cover the optional external executables or a researcher's installed plugins.

The clean wheel smoke check builds a distribution, creates a new virtual environment outside the checkout, installs the wheel with the TUI extra, verifies bundled configuration, profiles, scripts, and example plugin, then imports the CLI and TUI. It passed on Windows and Linux. CI is configured to run the full offline suite on Windows and Linux with Python 3.11, 3.12, and 3.13, plus source and wheel checks. The GitHub Actions matrix has not run because it requires an online repository action, which the local-only plan excludes. The local Linux 3.11 run used Docker after the attempted WSL run lost filesystem I/O when C: ran out of space. The disposable firmware validation cases were moved to D:, restoring space. Kali WSL still needs repair; the Docker validation does not depend on it.

## Real firmware cases

Both images were imported as hashed case evidence and analyzed with versioned run records. The OpenWrt image was pinned to the [24.10.4 ramips/mt76x8 official downloads](https://downloads.openwrt.org/releases/24.10.4/targets/ramips/mt76x8/): SHA-256 `7c18315ff6c9988c3d873d7dee484082995a26beb9ab257aef254982e75a7e76`. The user's local IoTGoat image hash was `320b88ec8bdd7cae9f99669275b3b0f48dfea5284af9d809fa5aa6ec6a792515`. Hashes identify the tested bytes; they do not authenticate an image without a separately trusted source checksum.

To reproduce an isolated local validation after building the tools image, run `python -m scripts.validate_firmware IMAGE --expected-sha256 DIGEST` from the repository root. The script uses a disposable case, prints the status and counts, and exits nonzero for incomplete analysis. The current container binds only the selected evidence file as input.

| Image and execution path | Result | Regular files | ELF files | Certificates | Candidate findings |
| --- | --- | ---: | ---: | ---: | ---: |
| OpenWrt, Windows Docker isolation | `complete` | 1,053 | 155 | 150 | 1 |
| OpenWrt, Windows trusted WSL | `complete` | 1,054 | 155 | 150 | 1 |
| OpenWrt, Linux trusted host | `complete` | 1,054 | 155 | 150 | 1 |
| IoTGoat, Windows Docker isolation | `complete` | 1,014 | 176 | 0 | 2 |
| IoTGoat, Windows trusted WSL | `complete` | 1,016 | 176 | 0 | 2 |
| IoTGoat, Linux trusted host | `complete` | 1,016 | 176 | 0 | 2 |

The differing regular-file counts come from extractor output artifacts rather than a different count of ELF payloads. OpenWrt's empty root password entry and IoTGoat's MD5-crypt entries are *candidates*; the run did not establish their reachability or exploitability. A selected OpenWrt `uhttpd` MIPS service was launched with QEMU user mode in the isolated container using its extracted root filesystem. It printed its usage information and exited with code 1 for the supplied `-h` argument, so the emulation run is recorded as `partial`. This demonstrates that the loader and process started; it is not a network-service or full-system boot test.

Constructed fixtures cover malformed SquashFS signatures, MBR offsets, ELF loaders and hardening, ARM/MIPS service selection, symlink traversal, an opaque image without an extractor, PEM/DER certificates, exact advisory-version matching, firmware diffs, and unavailable QEMU. Advisory snapshots are imported as hashed case evidence; matched candidates link both the firmware package and snapshot entry. Synthetic scan XML, APK, Frida, and packet inputs have expected-outcome tests, including specialist capture truncation and certificate signature verification. Endpoint, entropy, and RTP regression fixtures verify that ports, entropy, and RTP-like packet counts do not establish protocol security or cloud ownership. The case TUI test imports and analyzes evidence, records a named review, and exports a report. Workflow tests cover hostile conditions, interrupted checkpoints, changed-input rejection, case-folder relocation, and forged artifact paths. A real C210 firmware image and its physical board have not been obtained; these validation results say nothing about the purchased camera's hardware revision or firmware security.

## Release gate status

The CI release gate requires at least 80% overall line coverage and 90% branch coverage of the case, firmware, and workflow modules. All measured gates pass locally:

| Metric | Windows 3.11 | Windows 3.12 | Linux 3.11 | Linux 3.13 | Required |
| --- | ---: | ---: | ---: | ---: | ---: |
| Overall line coverage | 80.7% | 80.7% | 80.4% | 80.6% | 80% |
| Case branch coverage | 92.9% | 92.9% | 92.9% | 92.9% | 90% |
| Firmware branch coverage | 90.0% | 90.0% | 90.0% | 90.0% | 90% |
| Workflow branch coverage | 92.0% | 92.0% | 92.0% | 92.0% | 90% |

At that development stage, the broad Frida runner and some TUI paths accounted for most uncovered lines. Linux Python 3.12 and hosted CI had not run. The later release checks are recorded below.

## Local live checks

Live-device traffic and instrumentation require a researcher to invoke the relevant commands locally against an authorized target. Record the target, device firmware version, tool versions, and case evidence before running. Use an isolated network and import Nmap XML, PCAP, APK, firmware, and Frida logs into a case. Review and redact exports before sharing them. The public CI workflow does not schedule device jobs or upload lab artifacts.

## TUI consolidation validation (2026-11-17)

This section records the earlier layout. The 2026-11-18 review below supersedes its case and analysis navigation.

The dashboard now has one investigation route. Firmware analysis is part of the case screen; Scan and Frida put optional setup behind collapsible sections. Screenshot checks at 80×24 and 110×34 confirmed the primary actions stay visible. The new TUI tests also check that a configured default case still opens the dashboard, evidence selection infers the analyzer, and Settings does not render API key values.

After these changes, the full offline Windows Python 3.12 run collected 730 tests: 721 passed and 9 optional live checks skipped. The release coverage checks passed: 81.0% overall line coverage, 92.9% case branch coverage, 90.1% firmware branch coverage, and 92.0% workflow branch coverage. Focused TUI tests passed on Windows Python 3.11 before the final entrypoint regression test was added; that regression test and the final full suite passed on Python 3.12. A final scan input guard change was followed by six focused scan tests passing. Ruff, focused mypy, and `git diff --check` also passed. Python 3.13 and Linux were not rerun after this UI change; the earlier platform results above remain the prior baseline.

## Case picker and keyboard validation (2026-11-17)

The investigation screen now imports each evidence type through one form and selects the matching analyzer from the imported file. The firmware extraction environment appears only for firmware images and flash dumps. Case selection has a current/recent list, a path field with Tab completion, and a keyboard-browsable folder tree. The keyboard tests open, create, switch, and cancel cases; check the visible missing-case message; import and analyze Nmap XML without a mouse; and browse a folder with keys alone. Text entered in a path field does not trigger the single-letter case shortcuts.

The Windows Python 3.12 full offline run collected 735 tests: 726 passed and nine optional live checks skipped. Its coverage result passed the release gates: 80.8% overall line coverage, 92.9% case branch coverage, 90.1% firmware branch coverage, and 92.0% workflow branch coverage. The final folder-browser keyboard assertion was corrected to target Textual's focusable collapsible title; all 11 targeted UI tests then passed on Windows Python 3.11. Scoped Ruff, mypy, and `git diff --check` passed. Linux and Python 3.13 were not rerun for this picker change.

## Investigation and analysis review (2026-11-18)

The case-backed Analysis page now accepts imported firmware/flash dumps, Nmap XML, PCAP/PCAPNG, APKs, and Frida logs through an explicit evidence-to-analyzer catalog. The Investigation page handles import, review, and export. Manual-only file types have a disabled Run action and an explanation. Analysis history includes every run linked to the selected evidence, including workflow and imported results. Firmware extraction settings appear only for firmware inputs. The 80×24 TUI test checks that the primary Run action remains on screen. The scan adapter rejects non-Nmap XML roots and keeps service names and ambiguous UDP states as observations. APK decode limitations and JADX warning exits produce partial case runs. See `documentation/framework-review-2026-11-18.md` for the subsystem review and open limits.

| Environment | Full offline suite | Overall lines | Case branches | Firmware branches | Workflow branches |
| --- | ---: | ---: | ---: | ---: | ---: |
| Windows, Python 3.11.18 | 741 passed, 9 skipped | 81.2% | 94.6% | 90.1% | 92.0% |
| Windows, Python 3.12.4 | 741 passed, 9 skipped | 81.2% | 94.6% | 90.1% | 92.0% |
| Windows, Python 3.13.0 | 741 passed, 9 skipped | 81.2% | 94.6% | 90.1% | 92.0% |
| Linux Docker, Python 3.11.18 | 741 passed, 9 skipped | 81.0% | 94.6% | 90.1% | 92.0% |

Ruff's `E4,E7,E9,F` check, scoped mypy across 12 source files, and `git diff --check` passed. A clean source/wheel build passed Twine metadata checks. A new virtual environment imported the wheel, opened the CLI and TUI modules, read bundled assets, created a case, added evidence, and planned a workflow. The Python 3.11 focused UI/analyzer tests also passed before its full run. These are local runs; Linux Python 3.12/3.13, hosted CI, and a live device were not rerun for this change.

## Keyboard help discoverability (2026-11-18)

The TUI header now shows `F1 keyboard help`. The home, Investigation, and Analysis pages have visible Keys buttons. F1 opens navigation basics and screen-specific shortcuts, including while a path field is focused; the case picker has its own visible hints and contextual help. The 80×24 tests verify that the buttons remain on screen and the header text is rendered. A specialist scan screen also opens the combined guide with F1.

The full Windows Python 3.12 offline suite collected 753 tests: 744 passed, 9 optional live checks skipped. Coverage gates passed at 81.4% overall line coverage, 94.6% case branch coverage, 90.1% firmware branch coverage, and 92.0% workflow branch coverage. The focused keyboard/navigation suite passed 8 tests each on Windows Python 3.11 and 3.13 and Linux Docker Python 3.11. Ruff, the scoped mypy check including the app and help screens, and `git diff --check` passed. Hosted CI was not run.

## Analysis navigation and footer (2026-11-18)

The home now exposes case analysis, packet toolkit, and APK toolkit in one visible Analysis section. It names the case input types, while the case Analysis page selects a compatible analyzer from imported evidence and keeps firmware extraction settings conditional on firmware. The specialist tools remain standalone and say so in their screens and help. Their file paths now support Tab completion. A script path left in a collapsed field no longer causes script execution when a built-in packet or APK analysis runs. Visible specialist logs escape untrusted markup and redact obvious credential values.

The earlier header and Keys buttons were replaced with a context-aware bottom bar. It shows `F1 Help` and the active shortcuts; focused path fields show `Tab Complete path` and `Ctrl+Tab Next field`. F1 still opens a keyboard guide with screen-specific instructions. At 80×24, focused TUI tests verify the three Analysis choices, direct packet/APK routes, case Analysis, footer visibility, keyboard help, path completion, and the conditional custom-script behavior. The earlier Keyboard help discoverability section above records the previous design.

After this change, the full offline Windows Python 3.12 suite collected 756 tests: 747 passed and 9 optional live checks skipped. The coverage gates passed at 81.4% overall line coverage, 94.6% case branch coverage, 90.1% firmware branch coverage, and 92.0% workflow branch coverage. The 19 focused navigation and toolkit tests passed on Windows Python 3.12 and in local Linux Docker with Python 3.11. Ruff, scoped mypy across 18 source files, `git diff --check`, the clean source/wheel build, Twine metadata checks, and an offline clean wheel import passed. Windows Python 3.11/3.13 and hosted CI were not rerun for this change.

## Investigation navigation and Reports (2026-11-18)

The TUI now calls the saved folder an investigation throughout its visible controls. The home shows separate Firmware / flash, Packet captures, Android APK, Nmap XML, and Frida logs analysis entries. Each opens a filtered list of imported files; an empty list explains how to import the required type. The active investigation can be switched directly from the home. Reports is visible there and defaults to exporting that investigation, including reviewer decisions. Session and saved standalone results remain explicit alternative report sources. The file screen's Reports action opens the same report flow. The HTML report uses investigation wording while the `case` API and manifest schema remain stable.

At 80×24, tests check that all named analysis entries and Reports are on screen, the Reports export action is visible without scrolling, each entry selects only its matching file type, and the folder switch changes the report source. A full Windows Python 3.12 offline run collected 759 tests: 750 passed and 9 optional live checks skipped. Coverage gates passed at 81.5% overall line, 94.2% case branch, 90.1% firmware branch, and 92.0% workflow branch coverage. The 22 focused UI and manifest tests passed in local Linux Docker with Python 3.11. A transient Windows manifest sharing violation in the first full run led to a bounded read retry and a regression test; the final full run passed. After the full run, the HTML report label change passed its two targeted report tests. Ruff, scoped mypy across 19 files, `git diff --check`, the clean source/wheel build, Twine checks, and an offline wheel import passed. Hosted CI and live-device checks were not run.

## Pinned keyboard help (2026-11-18)

The `F1 Help` control is fixed at the right edge of the bottom bar on the home, Investigation, Analysis, Reports, and specialist screens. It opens the same contextual guide by click or F1; the case picker retains its visible modal hints. The 60×24 TUI tests check its location across all main routes and click it on Home, Investigation, Reports, and Scan. The full Windows Python 3.12 offline suite passed: 752 tests passed and 9 optional live checks skipped. Ruff's CI selection and scoped mypy across 20 files passed. Hosted CI was not run for this local change.

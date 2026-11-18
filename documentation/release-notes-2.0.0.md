# ChainRecon 2.0.0

ChainRecon 2.0 adds portable investigation folders that copy and hash raw evidence,
record analysis runs with tool provenance and coverage limits, and keep candidate
findings separate from researcher decisions. A rebuildable SQLite index supports
queries without becoming the source of truth.

## What changed

- Firmware analysis identifies image structure before extraction, records offsets
  and hashes, inventories an extracted filesystem, compares firmware versions,
  and offers guided QEMU user-mode service runs. Unknown images use the isolated
  container path by default; opaque images report incomplete analysis.
- Imported Nmap XML, packet captures, Android APKs, Frida logs, firmware images,
  and UART logs can be associated with an investigation. The TUI gives each
  supported analysis type a visible entry, with Reports on the home screen.
- Workflows use validated conditions and resumable runs. Report exports include
  evidence references and reviewer decisions, escape HTML and spreadsheet
  content, and redact sensitive values by default.
- The wheel includes default configuration, generic profiles, scripts, and the
  example plugin. Personal settings are stored outside the package.

## Validation and limits

The full offline suites on Windows Python 3.12 and Linux Python 3.11 each passed
761 tests with one skip.
The only skipped test requires a configured live Android emulator and Frida
server. Local coverage gates passed: 81.7% overall line coverage and at least
90% branch coverage in case, firmware, and workflow code. The wheel and source
archive passed metadata checks and clean install smoke tests on Windows Python
3.12 and Linux Python 3.11. Hosted GitHub Actions must pass before tagging.

Firmware findings are leads for review, not claims of exploitability. A physical
Tapo C210 device and a live Frida target were not part of this release test.
The v2 tree excludes earlier device-specific research files, but older public
Git commits may still contain them; see `documentation/history-cleanup.md`.

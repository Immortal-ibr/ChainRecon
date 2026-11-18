# Compatibility and retirement inventory

The old CLI scan, capture, APK, Frida, workflow, firmware, and report commands remain available during the 2.0 transition. They produce older result shapes. Import those JSON outputs into a case with `case import-v1` and review every imported risk indicator.

The `interactive` CLI alias now opens the case TUI. The old menu is inactive. The extended scanner no longer imports missing legacy modules; unsupported operations raise an explicit migration error. New analyses should use `case analyze`, `firmware analyze`, or a case-bound workflow.

Legacy material under `legacy/` is not packaged as part of the wheel. Treat examples there as historical references, inspect their contents before use, and do not use them as release evidence. Built-in Frida scripts are packaged under `chainrecon/runners/frida_scripts/`; custom executable scripts and plugins require analyst trust.

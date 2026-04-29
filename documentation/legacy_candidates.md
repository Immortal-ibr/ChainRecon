# Legacy Migration Notes

Moved to `legacy/` after approval:

- `runners/frida_scripts/framesBufferOld.js` -> `legacy/manual_frida_scripts/framesBufferOld.js`
- `runners/frida_scripts/load_script.ps1` -> `legacy/manual_frida_scripts/load_script.ps1`
- `scripts/*.sh` -> `legacy/manual_shell_scripts/*.sh`
- `Recon script.sh` -> `legacy/manual_shell_scripts/Recon script.sh`

Still already in legacy:

- `legacy/manual_frida_scripts/*`: older manual Frida helpers retained for reference.

Current active note:

- `scripts/network_setup.ps1`: still active on Windows; not moved.
- Active Frida scripts are under `runners/frida_scripts/`. The current set includes managed class discovery, device-wide class census, live loaded-class monitoring, Android networking hooks, crypto monitoring, SharedPreferences monitoring, and Nooie MQTT/token tracing. Older manual snippets should stay in `legacy/manual_frida_scripts/` unless they are converted to the managed runner contract.

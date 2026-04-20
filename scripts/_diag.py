"""Diagnostic script — run to dump network info and test config flow."""
import subprocess, json, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils.network import list_interfaces
from utils.config import get_network_config, save_network_config, reset_config

print("=== tshark interfaces ===")
ifaces = list_interfaces()
for i in ifaces:
    print(f"  name={i['name']!r:60s}  desc={i.get('description','')!r}")

print("\n=== PowerShell Get-NetAdapter (Up only) ===")
r = subprocess.run(
    ["powershell", "-NoProfile", "-Command",
     "Get-NetAdapter | Where-Object Status -eq Up | Select-Object Name,InterfaceDescription,Status | ConvertTo-Json"],
    capture_output=True, text=True, timeout=15,
)
if r.stdout.strip():
    adapters = json.loads(r.stdout)
    adapters = [adapters] if isinstance(adapters, dict) else adapters
    for a in adapters:
        print(f"  [{a['Status']:12}] {a['Name']:30} {a['InterfaceDescription']}")
else:
    print("  (no output)", r.stderr[:200])

print("\n=== Current network config ===")
reset_config()
cfg = get_network_config()
print(json.dumps(cfg, indent=2))

print("\n=== Test save_network_config ===")
save_network_config({
    "eth_interface": "Ethernet",
    "internet_interface": "Wi-Fi",
    "static_ip": "192.168.123.100/24",
    "target_ip": "192.168.123.50",
    "router_ip": "192.168.123.99",
})
reset_config()
cfg2 = get_network_config()
print(json.dumps(cfg2, indent=2))
assert cfg2["eth_interface"] == "Ethernet", "eth_interface not saved!"
assert cfg2["router_ip"] == "192.168.123.99", "router_ip not saved!"
print("PASS: network config save/load")

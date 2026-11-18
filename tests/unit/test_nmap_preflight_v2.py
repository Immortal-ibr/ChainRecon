"""Network preflight fixtures that never touch the user's actual network."""

from __future__ import annotations

import ipaddress
import socket
import subprocess
from unittest.mock import patch

from chainrecon.runners.nmap_runner import (
    _annotate_interface_context,
    _route_for_target,
    _selected_interface_networks,
    _target_in_networks,
    preflight_target,
)


def test_empty_and_range_targets_do_not_start_host_probes() -> None:
    with patch("chainrecon.runners.nmap_runner._ping_once") as ping:
        assert preflight_target("  ")["error"] == "empty target"
        assert preflight_target("192.0.2.0/24")["target_type"] == "cidr"
        assert preflight_target("192.0.2.1-10")["target_type"] == "range"
    ping.assert_not_called()


def test_host_preflight_distinguishes_dns_from_probe_reachability() -> None:
    with (
        patch("chainrecon.runners.nmap_runner._ping_once", return_value=False),
        patch("chainrecon.runners.nmap_runner._tcp_probe", side_effect=lambda host, port, timeout: {"port": port, "reachable": port == 443}),
    ):
        result = preflight_target("192.0.2.10")
    assert result["dns_resolved"] is True
    assert result["resolved_addresses"] == ["192.0.2.10"]
    assert result["icmp_echo"] is False
    assert len(result["tcp_probe"]) == 4
    assert result["tcp_probe"][1]["reachable"] is True


def test_dns_failure_is_recorded_without_reaching_target() -> None:
    with (
        patch("chainrecon.runners.nmap_runner.socket.getaddrinfo", side_effect=socket.gaierror("name unavailable")),
        patch("chainrecon.runners.nmap_runner._ping_once") as ping,
    ):
        result = preflight_target("no-such-host.example")
    assert result["dns_resolved"] is False
    assert "name unavailable" in result["dns_error"]
    ping.assert_not_called()


def test_selected_interface_mismatch_uses_route_evidence() -> None:
    info = {"target": "192.0.2.10", "interface_mismatch": False}
    with (
        patch("chainrecon.runners.nmap_runner._describe_selected_interface", return_value={"name": "eth4", "runtime_id": "eth4"}),
        patch("chainrecon.runners.nmap_runner._route_for_target", return_value={"name": "eth0", "runtime_id": "eth0"}),
        patch("chainrecon.runners.nmap_runner._selected_interface_networks", return_value=[]),
    ):
        _annotate_interface_context(info, "192.0.2.10", "eth4")
    assert info["interface_mismatch"] is True
    assert info["recommended_interface"]["runtime_id"] == "eth0"
    matching = {"target": "192.0.2.10", "interface_mismatch": False}
    with (
        patch("chainrecon.runners.nmap_runner._describe_selected_interface", return_value={"name": "eth0", "runtime_id": "eth0"}),
        patch("chainrecon.runners.nmap_runner._route_for_target", return_value={"name": "eth0", "runtime_id": "eth0"}),
        patch("chainrecon.runners.nmap_runner._selected_interface_networks", return_value=[]),
    ):
        _annotate_interface_context(matching, "192.0.2.10", "eth0")
    assert matching["interface_mismatch"] is False


def test_interface_subnet_is_inconclusive_without_route() -> None:
    networks = [ipaddress.ip_network("192.0.2.0/24")]
    assert _target_in_networks("192.0.2.10", networks) is True
    assert _target_in_networks("198.51.100.10", networks) is False
    assert _target_in_networks("invalid", networks) is None
    info = {"target": "198.51.100.10", "interface_mismatch": False}
    with (
        patch("chainrecon.runners.nmap_runner._describe_selected_interface", return_value={"name": "eth4", "runtime_id": "eth4"}),
        patch("chainrecon.runners.nmap_runner._route_for_target", return_value=None),
        patch("chainrecon.runners.nmap_runner._selected_interface_networks", return_value=networks),
    ):
        _annotate_interface_context(info, "198.51.100.10", "eth4")
    assert info["interface_mismatch"] is True
    assert info["recommended_interface"] is None


def test_linux_route_parser_and_windows_interface_networks() -> None:
    with (
        patch("chainrecon.runners.nmap_runner.platform.system", return_value="Linux"),
        patch("chainrecon.runners.nmap_runner.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "192.0.2.10 via 192.0.2.1 dev eth7 src 192.0.2.5", "")),
    ):
        assert _route_for_target("192.0.2.10")["runtime_id"] == "eth7"
    rows = '[{"InterfaceAlias":"Ethernet","IPAddress":"192.0.2.5","PrefixLength":24},{"InterfaceAlias":"Other","IPAddress":"198.51.100.2","PrefixLength":24}]'
    with (
        patch("chainrecon.runners.nmap_runner.platform.system", return_value="Windows"),
        patch("chainrecon.runners.nmap_runner.subprocess.run", return_value=subprocess.CompletedProcess([], 0, rows, "")),
    ):
        assert _selected_interface_networks({"name": "Ethernet", "runtime_id": "eth7"}) == [ipaddress.ip_network("192.0.2.0/24")]

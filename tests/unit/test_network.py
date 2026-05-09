"""Tests for utils/network.py — cross-platform network utilities."""

import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from chainrecon.utils import network


class ListInterfacesWindowsTests(unittest.TestCase):
    @patch("chainrecon.utils.network.is_windows", return_value=True)
    @patch("chainrecon.utils.platform_info.find_tool", return_value=r"C:\Wireshark\tshark.exe")
    @patch("chainrecon.utils.network.subprocess.run")
    def test_tshark_parsing(self, mock_run, *_):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            r"1. \Device\NPF_{ABC} (Ethernet)" "\n"
            r"2. \Device\NPF_{DEF} (Wi-Fi)" "\n",
            "",
        )
        ifaces = network._list_interfaces_windows()
        self.assertEqual(len(ifaces), 2)
        # name is now the friendly name (was description before)
        self.assertEqual(ifaces[0]["name"], "Ethernet")
        self.assertIn("Ethernet", ifaces[0]["description"])
        # device is the NPF path
        self.assertIn("NPF_", ifaces[0]["device"])

    @patch("chainrecon.utils.network.is_windows", return_value=True)
    @patch("chainrecon.utils.platform_info.find_tool", return_value=None)
    @patch("chainrecon.utils.network.subprocess.run")
    def test_powershell_fallback(self, mock_run, *_):
        adapters = [
            {"Name": "Ethernet", "InterfaceDescription": "Intel NIC", "Status": "Up"},
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, json.dumps(adapters), "",
        )
        ifaces = network._list_interfaces_windows()
        self.assertEqual(len(ifaces), 1)
        self.assertEqual(ifaces[0]["name"], "Ethernet")

    @patch("chainrecon.utils.network.is_windows", return_value=True)
    @patch("chainrecon.utils.platform_info.find_tool", return_value=None)
    @patch("chainrecon.utils.network.subprocess.run", side_effect=Exception("fail"))
    def test_all_fail_returns_empty(self, *_):
        ifaces = network._list_interfaces_windows()
        self.assertEqual(ifaces, [])

    @patch("chainrecon.utils.platform_info.find_tool", return_value=r"C:\Program Files (x86)\Nmap\nmap.exe")
    @patch("chainrecon.utils.network.subprocess.run")
    def test_list_nmap_interfaces_windows(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess(
            [],
            0,
            "DEV    WINDEVICE\n"
            "eth4   \\Device\\NPF_{DEF}\n"
            "eth0   \\Device\\NPF_{ABC}\n"
            "ROUTES\n",
            "",
        )
        mappings = network.list_nmap_interfaces_windows()
        self.assertEqual(mappings[0]["runtime_id"], "eth4")
        self.assertEqual(mappings[0]["device"], r"\Device\NPF_{DEF}")

    @patch("chainrecon.utils.network.is_windows", return_value=True)
    @patch("chainrecon.utils.network.list_interfaces")
    @patch("chainrecon.utils.network.list_nmap_interfaces_windows")
    def test_resolve_scan_interface_uses_nmap_runtime_id(self, mock_nmap, mock_ifaces, _):
        mock_ifaces.return_value = [
            {"name": "Wi-Fi", "device": r"\Device\NPF_{DEF}", "description": "Wi-Fi"},
        ]
        mock_nmap.return_value = [
            {"runtime_id": "eth4", "device": r"\Device\NPF_{DEF}"},
        ]
        resolved = network.resolve_scan_interface("Wi-Fi")
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["runtime_id"], "eth4")


class ListInterfacesLinuxTests(unittest.TestCase):
    @patch("chainrecon.utils.network.subprocess.run")
    def test_ip_link_parsing(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "1: lo: <LOOPBACK,UP> mtu 65536 state UP\n"
            "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP\n"
            "3: wlan0: <BROADCAST> mtu 1500 state DOWN\n",
            "",
        )
        ifaces = network._list_interfaces_linux()
        self.assertEqual(len(ifaces), 3)
        self.assertEqual(ifaces[0]["name"], "lo")
        self.assertEqual(ifaces[1]["description"], "UP")
        self.assertEqual(ifaces[2]["description"], "DOWN")

    @patch("chainrecon.utils.network.subprocess.run", side_effect=FileNotFoundError)
    def test_sys_class_fallback(self, _):
        from pathlib import Path
        with patch("pathlib.Path") as mock_path_cls:
            mock_dir = MagicMock()
            fake_eth = MagicMock()
            fake_eth.name = "eth0"
            fake_eth.is_dir.return_value = True
            mock_dir.exists.return_value = True
            mock_dir.iterdir.return_value = [fake_eth]
            mock_path_cls.return_value = mock_dir
            ifaces = network._list_interfaces_linux()
            self.assertEqual(len(ifaces), 1)
            self.assertEqual(ifaces[0]["name"], "eth0")


class DefaultGatewayTests(unittest.TestCase):
    @patch("chainrecon.utils.network.is_windows", return_value=True)
    @patch("chainrecon.utils.network.subprocess.run")
    def test_windows_gateway(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "192.168.1.1\n", "")
        gw = network.get_default_gateway()
        self.assertEqual(gw, "192.168.1.1")

    @patch("chainrecon.utils.network.is_windows", return_value=False)
    @patch("chainrecon.utils.network.subprocess.run")
    def test_linux_gateway(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "default via 10.0.0.1 dev eth0\n", "",
        )
        gw = network.get_default_gateway()
        self.assertEqual(gw, "10.0.0.1")

    @patch("chainrecon.utils.network.is_windows", return_value=True)
    @patch("chainrecon.utils.network.subprocess.run", side_effect=Exception("fail"))
    def test_failure_returns_none(self, *_):
        self.assertIsNone(network.get_default_gateway())


class LocalIPTests(unittest.TestCase):
    @patch("chainrecon.utils.network.socket.socket")
    def test_local_ip(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.getsockname.return_value = ("192.168.1.50", 0)
        mock_socket_cls.return_value = mock_sock
        self.assertEqual(network.get_local_ip(), "192.168.1.50")

    @patch("chainrecon.utils.network.socket.socket", side_effect=OSError)
    def test_failure_returns_none(self, _):
        self.assertIsNone(network.get_local_ip())


class IPForwardingTests(unittest.TestCase):
    @patch("chainrecon.utils.network.is_windows", return_value=True)
    @patch("chainrecon.utils.network.subprocess.run")
    def test_enable_windows(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(network.enable_ip_forwarding())

    @patch("chainrecon.utils.network.is_windows", return_value=True)
    @patch("chainrecon.utils.network.subprocess.run", side_effect=Exception("fail"))
    def test_enable_windows_failure(self, *_):
        self.assertFalse(network.enable_ip_forwarding())

    @patch("chainrecon.utils.network.is_windows", return_value=False)
    @patch("chainrecon.utils.network.subprocess.run")
    def test_enable_linux(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(network.enable_ip_forwarding())

    @patch("chainrecon.utils.network.is_windows", return_value=True)
    @patch("chainrecon.utils.network.subprocess.run")
    def test_disable_windows(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(network.disable_ip_forwarding())

    @patch("chainrecon.utils.network.is_windows", return_value=False)
    @patch("chainrecon.utils.network.subprocess.run")
    def test_disable_linux(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(network.disable_ip_forwarding())

    @patch("chainrecon.utils.network.is_windows", return_value=False)
    @patch("chainrecon.utils.network.subprocess.run", side_effect=Exception("fail"))
    def test_disable_failure(self, *_):
        self.assertFalse(network.disable_ip_forwarding())


if __name__ == "__main__":
    unittest.main()

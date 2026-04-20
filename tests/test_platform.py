"""Tests for utils/platform_info.py — cross-platform tool detection."""

import unittest
from unittest.mock import MagicMock, patch

from runners.base import ToolNotFoundError
from utils import platform_info


class OSDetectionTests(unittest.TestCase):
    @patch("utils.platform_info.platform.system", return_value="Windows")
    def test_get_os_windows(self, _):
        self.assertEqual(platform_info.get_os(), "windows")

    @patch("utils.platform_info.platform.system", return_value="Linux")
    def test_get_os_linux(self, _):
        self.assertEqual(platform_info.get_os(), "linux")

    @patch("utils.platform_info.platform.system", return_value="Darwin")
    def test_get_os_darwin(self, _):
        self.assertEqual(platform_info.get_os(), "darwin")

    @patch("utils.platform_info.get_os", return_value="windows")
    def test_is_windows_true(self, _):
        self.assertTrue(platform_info.is_windows())

    @patch("utils.platform_info.get_os", return_value="linux")
    def test_is_windows_false(self, _):
        self.assertFalse(platform_info.is_windows())

    @patch("utils.platform_info.get_os", return_value="linux")
    def test_is_linux_true(self, _):
        self.assertTrue(platform_info.is_linux())

    @patch("utils.platform_info.get_os", return_value="darwin")
    def test_is_mac_true(self, _):
        self.assertTrue(platform_info.is_mac())


class FindToolTests(unittest.TestCase):
    @patch("utils.platform_info.shutil.which", return_value="/usr/bin/nmap")
    def test_found_on_path(self, _):
        self.assertEqual(platform_info.find_tool("nmap"), "/usr/bin/nmap")

    @patch("utils.platform_info.shutil.which", return_value=None)
    @patch("utils.platform_info.is_windows", return_value=False)
    def test_not_found_returns_none(self, *_):
        self.assertIsNone(platform_info.find_tool("nmap"))

    @patch("utils.platform_info.is_windows", return_value=True)
    @patch("utils.platform_info.shutil.which")
    def test_windows_exe_fallback(self, mock_which, _):
        """On Windows, tries name.exe if name not found."""
        mock_which.side_effect = lambda n: r"C:\nmap\nmap.exe" if n == "nmap.exe" else None
        self.assertEqual(platform_info.find_tool("nmap"), r"C:\nmap\nmap.exe")

    @patch("utils.platform_info.is_windows", return_value=True)
    @patch("utils.platform_info.shutil.which", return_value=None)
    @patch("utils.platform_info.os.path.isdir", return_value=True)
    @patch("utils.platform_info.os.path.isfile")
    def test_windows_install_dir_search(self, mock_isfile, *_):
        mock_isfile.side_effect = lambda p: "nmap.exe" in p
        result = platform_info.find_tool("nmap")
        self.assertIsNotNone(result)
        self.assertIn("nmap", result)

    @patch("utils.platform_info.shutil.which", return_value=None)
    @patch("utils.platform_info.is_windows", return_value=False)
    @patch("utils.platform_info.os.path.isdir", return_value=True)
    @patch("utils.platform_info.os.path.isfile", return_value=True)
    def test_extra_paths_checked(self, *_):
        result = platform_info.find_tool("mytool", extra_paths=["/opt/tools"])
        self.assertIsNotNone(result)


class RequireToolTests(unittest.TestCase):
    @patch("utils.platform_info.find_tool", return_value="/usr/bin/nmap")
    def test_success(self, _):
        self.assertEqual(platform_info.require_tool("nmap"), "/usr/bin/nmap")

    @patch("utils.platform_info.find_tool", return_value=None)
    @patch("utils.platform_info.is_windows", return_value=False)
    def test_raises_on_missing(self, *_):
        with self.assertRaises(ToolNotFoundError):
            platform_info.require_tool("nmap")

    @patch("utils.platform_info.find_tool", return_value=None)
    @patch("utils.platform_info.is_windows", return_value=True)
    def test_windows_error_includes_locations(self, *_):
        with self.assertRaises(ToolNotFoundError) as ctx:
            platform_info.require_tool("nmap")
        self.assertIn("Program Files", str(ctx.exception))


class CheckAllToolsTests(unittest.TestCase):
    @patch("utils.platform_info.find_tool")
    def test_returns_all_tools(self, mock_find):
        mock_find.return_value = None
        status = platform_info.check_all_tools()
        self.assertIn("nmap", status)
        self.assertIn("tshark", status)
        self.assertIn("adb", status)
        self.assertIn("frida", status)
        self.assertEqual(len(status), 9)

    @patch("utils.platform_info.find_tool", return_value="/usr/bin/nmap")
    def test_found_tool_entry(self, _):
        status = platform_info.check_all_tools()
        self.assertTrue(status["nmap"]["found"])
        self.assertEqual(status["nmap"]["path"], "/usr/bin/nmap")


class MiscTests(unittest.TestCase):
    def test_get_architecture(self):
        arch = platform_info.get_architecture()
        self.assertIsInstance(arch, str)
        self.assertTrue(len(arch) > 0)

    def test_get_python_version(self):
        ver = platform_info.get_python_version()
        self.assertRegex(ver, r"\d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()

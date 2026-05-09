"""Tests for utils.logging_config module."""

import logging
import unittest

from chainrecon.utils.logging_config import get_logger, reset_logging, setup_logging


class SetupLoggingTests(unittest.TestCase):
    def setUp(self):
        reset_logging()

    def tearDown(self):
        reset_logging()

    def test_returns_chainrecon_logger(self):
        logger = setup_logging()
        self.assertEqual(logger.name, "chainrecon")

    def test_default_level_is_info(self):
        logger = setup_logging()
        self.assertEqual(logger.level, logging.INFO)

    def test_verbose_sets_debug(self):
        logger = setup_logging(verbose=True)
        self.assertEqual(logger.level, logging.DEBUG)

    def test_idempotent_without_reset(self):
        logger1 = setup_logging(verbose=False)
        logger2 = setup_logging(verbose=True)
        self.assertIs(logger1, logger2)
        # Level stays INFO because second call is a no-op
        self.assertEqual(logger2.level, logging.INFO)

    def test_reset_allows_reconfigure(self):
        setup_logging(verbose=False)
        reset_logging()
        logger = setup_logging(verbose=True)
        self.assertEqual(logger.level, logging.DEBUG)

    def test_log_file_handler(self):
        import os
        import tempfile

        tmp = tempfile.mkdtemp()
        log_path = os.path.join(tmp, "sub", "test.log")
        try:
            logger = setup_logging(log_file=log_path)
            logger.info("hello from test")
            # Flush all handlers
            for h in logger.handlers:
                h.flush()
            self.assertTrue(os.path.isfile(log_path))
            content = open(log_path, encoding="utf-8").read()
            self.assertIn("hello from test", content)
        finally:
            # Release file handles before cleanup
            reset_logging()
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_has_at_least_one_handler(self):
        logger = setup_logging()
        self.assertGreaterEqual(len(logger.handlers), 1)


class GetLoggerTests(unittest.TestCase):
    def test_child_logger(self):
        logger = get_logger("scan")
        self.assertEqual(logger.name, "chainrecon.scan")

    def test_root_name(self):
        logger = get_logger("chainrecon")
        self.assertEqual(logger.name, "chainrecon")


class CLIVerboseTests(unittest.TestCase):
    """Verify that --verbose flag is accepted by the CLI parser."""

    def setUp(self):
        reset_logging()

    def tearDown(self):
        reset_logging()

    def test_parser_accepts_verbose(self):
        from chainrecon import build_parser
        parser = build_parser()
        args = parser.parse_args(["--verbose", "analyze-traffic", "dummy.txt"])
        self.assertTrue(args.verbose)

    def test_parser_accepts_log_file(self):
        from chainrecon import build_parser
        parser = build_parser()
        args = parser.parse_args(["--log-file", "out.log", "analyze-traffic", "dummy.txt"])
        self.assertEqual(args.log_file, "out.log")


if __name__ == "__main__":
    unittest.main()

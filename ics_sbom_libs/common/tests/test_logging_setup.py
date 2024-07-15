# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import unittest
import logging
import io

import argparse

from ics_sbom_libs.common import logging_setup


class TestLogging(unittest.TestCase):
    def test_logging(self):
        with self.assertLogs("foo", level="INFO") as cm:
            logging.getLogger("foo").info("first message")
            logging.getLogger("foo.bar").error("second message")
        self.assertEqual(cm.output, ["INFO:foo:first message", "ERROR:foo.bar:second message"])


def _log_level_tester(level: int | str):

    level_name: str = ""
    if isinstance(level, str):
        level_name = level
    else:
        level_name = logging.getLevelName(level)

    log_stream = io.StringIO()
    logging.basicConfig(level=level, stream=log_stream, force=True)

    log = logging.getLogger(level_name.lower() + "_test")

    log.debug("debug message")
    log.info("info message")
    log.warning("warning message")
    log.error("error message")
    log.critical("critical message")

    value = log_stream.getvalue()

    return value


class TestLogLevels(unittest.TestCase):

    def test_debug_log(self):
        test_level = logging.DEBUG
        test_name = logging.getLevelName(test_level).lower()
        result = _log_level_tester(test_level)

        self.assertEqual(
            result,
            f"DEBUG:{test_name}_test:debug message\n"
            f"INFO:{test_name}_test:info message\n"
            f"WARNING:{test_name}_test:warning message\n"
            f"ERROR:{test_name}_test:error message\n"
            f"CRITICAL:{test_name}_test:critical message\n",
        )

    def test_info_log(self):
        test_level = logging.INFO
        test_name = logging.getLevelName(test_level).lower()
        result = _log_level_tester(test_level)

        self.assertEqual(
            result,
            f"INFO:{test_name}_test:info message\n"
            f"WARNING:{test_name}_test:warning message\n"
            f"ERROR:{test_name}_test:error message\n"
            f"CRITICAL:{test_name}_test:critical message\n",
        )

    def test_warning_log(self):
        test_level = logging.WARNING
        test_name = logging.getLevelName(test_level).lower()
        result = _log_level_tester(test_level)

        self.assertEqual(
            result,
            f"WARNING:{test_name}_test:warning message\n"
            f"ERROR:{test_name}_test:error message\n"
            f"CRITICAL:{test_name}_test:critical message\n",
        )

    def test_error_log(self):
        test_level = logging.ERROR
        test_name = logging.getLevelName(test_level).lower()
        result = _log_level_tester(test_level)

        self.assertEqual(
            result, f"ERROR:{test_name}_test:error message\n" f"CRITICAL:{test_name}_test:critical message\n"
        )


class TestArgParsedLogLevels(unittest.TestCase):

    @staticmethod
    def _parse_args(args):
        parser = argparse.ArgumentParser()
        logging_setup.setup_log_arg(parser)

        return parser.parse_args(args)

    def test_debug_log(self):
        test_level = logging.DEBUG
        test_name = logging.getLevelName(test_level).lower()

        args = self._parse_args(["--log", test_name])
        result = _log_level_tester(logging_setup.handle_log_arg(args))

        self.assertEqual(
            result,
            f"DEBUG:{test_name}_test:debug message\n"
            f"INFO:{test_name}_test:info message\n"
            f"WARNING:{test_name}_test:warning message\n"
            f"ERROR:{test_name}_test:error message\n"
            f"CRITICAL:{test_name}_test:critical message\n",
        )

    def test_debug_log_2(self):
        test_level = logging.DEBUG
        test_name = logging.getLevelName(test_level).lower()

        args = self._parse_args([f"--log={test_name}"])
        result = _log_level_tester(logging_setup.handle_log_arg(args))

        self.assertEqual(
            result,
            f"DEBUG:{test_name}_test:debug message\n"
            f"INFO:{test_name}_test:info message\n"
            f"WARNING:{test_name}_test:warning message\n"
            f"ERROR:{test_name}_test:error message\n"
            f"CRITICAL:{test_name}_test:critical message\n",
        )

    def test_info_log(self):
        test_level = logging.INFO
        test_name = logging.getLevelName(test_level).lower()

        args = self._parse_args(["--log", test_name])
        result = _log_level_tester(logging_setup.handle_log_arg(args))

        self.assertEqual(
            result,
            f"INFO:{test_name}_test:info message\n"
            f"WARNING:{test_name}_test:warning message\n"
            f"ERROR:{test_name}_test:error message\n"
            f"CRITICAL:{test_name}_test:critical message\n",
        )

    def test_warning_log(self):
        test_level = logging.WARNING
        test_name = logging.getLevelName(test_level).lower()

        args = self._parse_args(["--log", test_name])
        result = _log_level_tester(logging_setup.handle_log_arg(args))

        self.assertEqual(
            result,
            f"WARNING:{test_name}_test:warning message\n"
            f"ERROR:{test_name}_test:error message\n"
            f"CRITICAL:{test_name}_test:critical message\n",
        )

    def test_error_log(self):
        test_level = logging.ERROR
        test_name = logging.getLevelName(test_level).lower()

        args = self._parse_args(["--log", test_name])
        result = _log_level_tester(logging_setup.handle_log_arg(args))

        self.assertEqual(
            result, f"ERROR:{test_name}_test:error message\n" f"CRITICAL:{test_name}_test:critical message\n"
        )


if __name__ == "__main__":
    unittest.main()

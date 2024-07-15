# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import argparse

__all__ = ["setup_log_arg", "handle_log_arg"]

_logList = ["NOTSET", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
_log_default_level = "WARNING"


def setup_log_arg(parser: argparse.ArgumentParser):
    if not parser:
        return

    parser.add_argument("--log", type=str, default=_log_default_level, help="Set The Log level of the application")


def handle_log_arg(args: argparse.Namespace):
    if not args or args.log is None:
        return _log_default_level

    log_value = args.log.upper()
    return log_value if log_value in _logList else _log_default_level

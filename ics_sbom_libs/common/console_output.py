# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

from rich.text import Text
from rich import print
from rich.style import Style
from rich.console import Console

import textwrap

from typing import Final

column_fmt_default_size: Final = 20
column_fmt_left_str = "{:<" + f"{column_fmt_default_size}" + "}"
column_fmt_right_str = "{:>" + f"{column_fmt_default_size}" + "}"


def format_string(prop: str, value: str = "", style: str | Style = "bold cyan", left_justify: bool = True):
    prop_fmtd_string = f"{column_fmt_left_str.format(prop)}" if left_justify else f"{column_fmt_right_str.format(prop)}"
    return Text.assemble((prop_fmtd_string, style), ("  :  ", "yellow"), f"{value}")


def print_list(name: str, data_list: list, with_wrap: bool = False):

    if not data_list or len(data_list) == 0:
        print(format_string(name, "None\n"))
        return

    name_str = format_string(name)

    column_spacer = ("{:<" + f"{name_str.cell_len}" + "}").format(" ")
    list_str = ""
    if with_wrap:
        tab_width = len(max(data_list, key=len)) + 3
        list_str = textwrap.fill(
            "\t".join(data_list),
            width=Console().width,
            initial_indent=column_spacer,
            subsequent_indent=column_spacer,
            tabsize=tab_width,
        ).strip()
    else:
        list_str = ("\n" + column_spacer).join(data_list)

    print(format_string(name) + list_str)

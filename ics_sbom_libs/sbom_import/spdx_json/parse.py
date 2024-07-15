# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import json

from beartype.typing import Dict
from spdx_tools.spdx.model import Document as SPDXDocument
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser

_replacement_symbols = {"&": "AND", "|": "OR"}


def parse_from_json(file):
    input_doc_as_dict: Dict = json.load(file)

    if "packages" in input_doc_as_dict.keys():
        for package in input_doc_as_dict["packages"]:
            if "licenseDeclared" in package.keys():
                new_string = package["licenseDeclared"]
                for symbol in _replacement_symbols:
                    new_string = new_string.replace(symbol, _replacement_symbols[symbol])

                package["licenseDeclared"] = new_string

    return JsonLikeDictParser().parse(input_doc_as_dict)


def parse_from_json_file(file_name: str, encoding: str = "utf-8") -> SPDXDocument:
    with open(file_name, encoding=encoding) as file:
        return parse_from_json(file)

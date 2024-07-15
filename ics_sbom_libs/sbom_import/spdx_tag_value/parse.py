# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import re

from spdx_tools.spdx.model import Document as SPDXDocument
from spdx_tools.spdx.parser.tagvalue.parser import Parser as TagValueParser

from ics_sbom_libs.sbom_import.spdx_tag_value.filter_lexers import SimplifiedFilterLexer
from ics_sbom_libs.sbom_import.spdx_tag_value.progress_lexer import ProgressLexer


def parse_from_tag_value_file(file_name: str, encoding: str = "utf-8") -> SPDXDocument:
    parser = TagValueParser()
    parser.lex = ProgressLexer(SimplifiedFilterLexer())
    parser.lex.build(reflags=re.UNICODE)
    with open(file_name, encoding=encoding) as file:
        data = file.read()
    document: SPDXDocument = parser.parse(data)
    return document

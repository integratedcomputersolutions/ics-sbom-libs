# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

from ply.lex import TOKEN
from spdx_tools.spdx.parser.tagvalue.lexer import SPDXLexer


class SimplifiedFilterLexer(SPDXLexer):
    @TOKEN(r"\s*Relationship:.+")
    def t_RELATIONSHIP(self, t):
        pass

    @TOKEN(r"\s*RelationshipComment:.+")
    def t_RELATIONSHIP_COMMENT(self, t):
        pass

    @TOKEN(r"\s*FileName:.+")
    def t_FILE_NAME(self, t):
        pass

    @TOKEN(r"\s*FileType:.+")
    def t_FILE_TYPE(self, t):
        pass

    @TOKEN(r"\s*FileChecksum:.+")
    def t_FILE_CHECKSUM(self, t):
        pass

    @TOKEN(r"\s*LicenseConcluded:.+")
    def t_FILE_LICENSE_CONCLUDED(self, t):
        pass

    @TOKEN(r"\s*LicenseInfoInFile:.+")
    def t_FILE_LICENSE_INFO(self, t):
        pass

    @TOKEN(r"\s*FileCopyrightText:.+")
    def t_FILE_COPYRIGHT_TEXT(self, t):
        pass

    @TOKEN(r"\s*LicenseComments:.+")
    def t_FILE_LICENSE_COMMENT(self, t):
        pass

    @TOKEN(r"\s*FileComment:.+")
    def t_FILE_COMMENT(self, t):
        pass

    @TOKEN(r"\s*FileNotice:.+")
    def t_FILE_NOTICE(self, t):
        pass

    @TOKEN(r"\s*FileContributor:.+")
    def t_FILE_CONTRIBUTOR(self, t):
        pass

    @TOKEN(r"\s*FileAttributionText:.+")
    def t_FILE_ATTRIBUTION_TEXT(self, t):
        pass

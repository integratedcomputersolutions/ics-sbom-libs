# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

from tqdm import tqdm
from ply import lex


class ProgressLexer:
    _progress: tqdm or None = None
    _lexer: lex or None = None

    def __init__(self, lexer):
        if lexer is not None:
            self._lexer = lexer

        self._last_pos = 0
        self._delta_pos = 0

    def build(self, **kwargs):
        self._lexer.build(**kwargs)

    def token(self):
        value = self._lexer.token()

        self._delta_pos = self._lexer.lexer.lexpos - self._last_pos
        self._last_pos = self._lexer.lexer.lexpos

        if self._progress is None:
            self._progress = tqdm(total=self._lexer.lexer.lexlen, desc="Reading SBoM", unit="b")

        self._progress.update(self._delta_pos)

        if value is None or value.type == "eof":
            self._progress.close()
        return value

    def input(self, data):
        self._lexer.input(data)

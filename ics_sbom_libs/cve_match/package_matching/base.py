# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import semantic_version


invalid_version_list = ["", "*", "-"]


class VersionHandler:

    def __init__(self):
        self._package = ""
        self._type = semantic_version.Version

    @property
    def package(self):
        return self._package

    @property
    def version_type(self):
        return self._type

    def convert(self, ver: str) -> str | semantic_version.Version:
        return ver

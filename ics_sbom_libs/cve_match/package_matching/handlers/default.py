# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import semantic_version

from ics_sbom_libs.cve_match.package_matching import VersionHandler, invalid_version_list


class DefaultVersionHandler(VersionHandler):

    def __init__(self):
        super(DefaultVersionHandler, self).__init__()
        self._package = "default"
        self._type = semantic_version.Version

    def convert(self, ver: str) -> str | semantic_version.Version:
        try:
            pkg_version = self.version_type.coerce(ver) if ver not in invalid_version_list else ver
        except ValueError:
            pkg_version = ver

        return pkg_version

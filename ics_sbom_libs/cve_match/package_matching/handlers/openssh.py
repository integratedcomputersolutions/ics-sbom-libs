# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import semantic_version

from ics_sbom_libs.cve_match.package_matching import VersionHandler, invalid_version_list


class OpenSSHVersionHandler(VersionHandler):

    def __init__(self):
        super(OpenSSHVersionHandler, self).__init__()
        self._package = "openssh"
        self._type = semantic_version.Version

    def convert(self, ver: str) -> str | semantic_version.Version:
        if ver in invalid_version_list:
            return ver

        if ver.find("p") != -1:
            ver = ver[:-2]

        try:
            pkg_version = self.version_type.coerce(ver)
            return pkg_version

        except ValueError:
            return ver

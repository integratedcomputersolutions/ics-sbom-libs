# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import re

import semantic_version

from ics_sbom_libs.cve_match.package_matching.buildversion import BuildVersion
from ics_sbom_libs.cve_match.package_matching import VersionHandler, invalid_version_list


class OpenSSLVersionHandler(VersionHandler):
    def __init__(self):
        super(OpenSSLVersionHandler, self).__init__()
        self._package = "openssl"
        self._type = BuildVersion

    def convert(self, ver: str) -> str | semantic_version.Version:
        if ver in invalid_version_list:
            return ver

        parts = ver.split(".")
        if len(parts) not in [3, 4]:
            return ver

        offset = 0
        if len(parts) == 4:
            offset = 1

        major = parts[offset]
        minor = parts[offset + 1]
        patch = parts[offset + 2]

        # split patch to patch/build
        patch_parts = re.split(r"(\d+)", patch)
        patch = patch_parts[1]
        build = patch_parts[2]

        if offset != 1:
            pkg_version = self.version_type.coerce(f"{major}.{minor}.{patch}+{build}")
        else:
            pkg_version = self.version_type.coerce(f"{major}.{minor}.{patch}-{parts[0]}+{build}")

        return pkg_version

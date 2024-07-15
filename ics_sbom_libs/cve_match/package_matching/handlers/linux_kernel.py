# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import semantic_version

from ics_sbom_libs.cve_match.package_matching.buildversion import BuildVersion
from ics_sbom_libs.cve_match.package_matching import VersionHandler, invalid_version_list


class LinuxKernelVersionHandler(VersionHandler):
    def __init__(self):
        super(LinuxKernelVersionHandler, self).__init__()
        self._package = "linux_kernel"
        self._type = BuildVersion

    def convert(self, ver: str) -> str | semantic_version.Version:
        if ver in invalid_version_list:
            return ver

        if ver.count("-") == 0:
            pkg_version = self.version_type.coerce(ver)
        else:
            parts = ver.split("-")
            if len(parts) != 2:

                return ver

            # for yocto platform type packages like linux-toradex the version of the kernel is before the '-'
            pkg_version = self.version_type.coerce(version_string=parts[0])

        return pkg_version

# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

from cpeparser import CpeParser
from ics_sbom_libs.common.vulnerability import Vulnerability


class CpeMatchResult:

    def __init__(self, cpe: str):
        self._cpe = cpe
        self._parsed = CpeParser().parser(self._cpe)
        self._cve_list: list[Vulnerability] = []

    def append_cve(self, cve: Vulnerability):
        if cve not in self._cve_list:
            self._cve_list.append(cve)

    @property
    def product(self):
        return self._parsed["product"]

    @property
    def vendor(self):
        return self._parsed["vendor"]

    @property
    def version(self):
        return self._parsed["version"]

    @property
    def cve_list(self):
        return self._cve_list

    @property
    def cpe(self):
        return self._cpe

    def get_cpe_properties(self):
        return self.vendor, self.product, self.version

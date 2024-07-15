# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Chris Rizzitello <crizzitello@ics.com>
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

from ics_sbom_libs.common.vulnerability import Vulnerability


class MatchResult:

    def __init__(self, name: str, version: str, cpes: list[str] = None):
        self.cve_list: list[Vulnerability] = []
        self.name = name
        self.version = version
        self.cpe_list: list[str] = cpes if cpes else []

    def append_cve(self, cve: Vulnerability):
        if cve not in self.cve_list:
            self.cve_list.append(cve)

    def get_severity_info(self):
        severity_counts = {"NONE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for item in self.cve_list:
            severity_counts[item.severity] += 1

        return severity_counts

    @property
    def stringify(self):
        line = f'{self.name} ({self.version})[{" ".join(self.cpe_list)}]: Has {len(self.cve_list)} CVEs'
        severity_info = self.get_severity_info()
        for severity in severity_info.keys():
            line += f" {severity}: {severity_info[severity]}"
        if not self.cve_list:
            line += "!"
        else:
            line += ": " + " ".join((item.cve_number for item in self.cve_list))
        return line

    @property
    def csvify(self):
        out = f'{self.name},{self.version},{" ".join(self.cpe_list)},{len(self.cve_list)},'
        severity_info = self.get_severity_info()
        for severity in severity_info.keys():
            out += f"{severity_info[severity]},"
        if self.cve_list:
            out = out + f'{" ".join((item.cve_number for item in self.cve_list))}'
        return out

    def print_result(self):
        print(self.stringify)

    def __lt__(self, other):
        return self.name < other.name

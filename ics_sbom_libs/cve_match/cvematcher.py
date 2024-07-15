# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Chris Rizzitello <crizzitello@ics.com>
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>
# SPDX-FileContributor: Milo Kerr <mkerr@ics.com>

import datetime
import os

from enum import Enum
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

from .matchresult import MatchResult
import semantic_version
import pathlib

from rich import table
from cpeparser import CpeParser
from spdx_tools.spdx.model import Document as SPDXDocument
from spdx_tools.spdx.model import ExternalPackageRefCategory

from ics_sbom_libs.cve_match.package_matching.versionfactory import VersionFactory
from ics_sbom_libs.cve_match.cpe_match_results import CpeMatchResult

from ics_sbom_libs.common.vulnerability import vulnerability_styles
from ics_sbom_libs.cve_fetch.vulnerabilitydatabase import VulnerabilityDatabase


class MatchTableOutput(Enum):
    CvesOnly = 1
    WithoutCvesOnly = 2
    All = 3


class CveMatcher:
    def __init__(self, spdx_document: SPDXDocument, db_path: pathlib.Path):
        self.resultList: list[MatchResult] = []
        self.spdx_document = spdx_document
        self.db_path = db_path
        self.totalPackages = len(self.spdx_document.packages)
        self.dirtyPackages = 0
        self.cleanPackages = 0
        self.totalCves = 0

        self.resultList = process(self.spdx_document, self.db_path)
        self.scanTime = str(datetime.datetime.utcnow()).replace(" ", "T")[:-7] + "Z"

        for result in self.resultList:
            if result.cve_list:
                self.dirtyPackages += 1
                self.totalCves += len(result.cve_list)
            else:
                self.cleanPackages += 1

    def create_match_table(self, table_output: MatchTableOutput = MatchTableOutput.All):
        match_table = table.Table(title="CVE Results", row_styles=["dim", ""])
        match_table.add_column(header="Package", style="green")
        match_table.add_column(header="Version", style="magenta")
        match_table.add_column(header="CVE Count", style="blue")
        match_table.add_column(header="None", style=vulnerability_styles["NONE"])
        match_table.add_column(header="Low", style=vulnerability_styles["LOW"])
        match_table.add_column(header="Medium", style=vulnerability_styles["MEDIUM"])
        match_table.add_column(header="High", style=vulnerability_styles["HIGH"])
        match_table.add_column(header="Critical", style=vulnerability_styles["CRITICAL"])
        match_table.add_column(header="CVEs")

        vuln_info_counts = {"Total": 0, "NONE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for result in self.resultList:
            vuln_info = result.get_severity_info()
            if result.cve_list and table_output != MatchTableOutput.WithoutCvesOnly:
                match_table.add_row(
                    f"{result.name}",
                    f"{result.version}",
                    f"{len(result.cve_list)}",
                    f'{vuln_info["NONE"]}',
                    f'{vuln_info["LOW"]}',
                    f'{vuln_info["MEDIUM"]}',
                    f'{vuln_info["HIGH"]}',
                    f'{vuln_info["CRITICAL"]}',
                    f'{" ".join(cve.cve_number for cve in result.cve_list)}',
                )

                vuln_info_counts["Total"] += len(result.cve_list)
                for severity in list(vuln_info_counts.keys())[1:]:
                    vuln_info_counts[severity] += vuln_info[severity]

            elif not result.cve_list and table_output != MatchTableOutput.CvesOnly:
                match_table.add_row(
                    f"{result.name}",
                    f"{result.version}",
                    f"{len(result.cve_list)}",
                    f'{vuln_info["NONE"]}',
                    f'{vuln_info["LOW"]}',
                    f'{vuln_info["MEDIUM"]}',
                    f'{vuln_info["HIGH"]}',
                    f'{vuln_info["CRITICAL"]}',
                    "",
                )

        match_table.add_section()
        match_table.add_row(
            "Totals",
            "",
            f'{vuln_info_counts["Total"]}',
            f'{vuln_info_counts["NONE"]}',
            f'{vuln_info_counts["LOW"]}',
            f'{vuln_info_counts["MEDIUM"]}',
            f'{vuln_info_counts["HIGH"]}',
            f'{vuln_info_counts["CRITICAL"]}',
            "",
        )
        return match_table

    def get_severity_info(self):
        vuln_info_counts = {"Total": 0, "NONE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for result in self.resultList:
            vuln_info = result.get_severity_info()
            vuln_info_counts["Total"] += len(result.cve_list)
            for severity in list(vuln_info_counts.keys())[1:]:
                vuln_info_counts[severity] += vuln_info[severity]

        return vuln_info_counts

    def __str__(self):
        return str(self.create_match_table())


def process(spdx_document: SPDXDocument, db_path: pathlib.Path):
    results_list = []
    unique_cpes = {}
    use_parallel = os.environ["MATCH_USE_PARALLEL"].upper() == "TRUE" if "MATCH_USE_PARALLEL" in os.environ else True
    match_results = {}

    package_pbar = tqdm(
        total=len(spdx_document.packages), desc="Matching CPEs", unit="packages", mininterval=0, miniters=1
    )
    if use_parallel:
        with ProcessPoolExecutor() as executor:
            future_to_package = {
                executor.submit(process_package, package, db_path): package for package in spdx_document.packages
            }
            for future in as_completed(future_to_package):
                package = future_to_package[future]
                result, unique_cpes_partial = future.result()
                match_results.update(result)
                for cpe, packages in unique_cpes_partial.items():
                    if cpe not in unique_cpes:
                        unique_cpes[cpe] = packages
                    else:
                        unique_cpes[cpe].extend(packages)
                package_pbar.update()
    else:
        for package in spdx_document.packages:
            result, unique_cpes_partial = process_package(package, db_path)
            match_results.update(result)
            for cpe, packages in unique_cpes_partial.items():
                if cpe not in unique_cpes:
                    unique_cpes[cpe] = packages
                else:
                    unique_cpes[cpe].extend(packages)
            package_pbar.update()

    pbar = tqdm(total=len(unique_cpes), desc="Checking CPEs for Known Issues", unit="cpes", mininterval=0, miniters=1)
    if use_parallel:
        with ProcessPoolExecutor() as executor:
            future_result = {executor.submit(find_cves_for_cpe, cpe, db_path): cpe for cpe in unique_cpes}

            for result in as_completed(future_result):
                results_list.append(result.result())
                pbar.update()

    else:
        for cpe in unique_cpes:
            result = find_cves_for_cpe(cpe, db_path)
            results_list.append(result)
            pbar.update()

    for cpe in results_list:
        if not cpe.cve_list:
            continue

        for package in unique_cpes[cpe.cpe]:
            match_results[package.name].cve_list += cpe.cve_list
            break

    return list(match_results.values())


def lookup_cpe_for_package(package_name: str, db_path: pathlib.Path) -> list[str] | None:
    db = VulnerabilityDatabase(db_path.parent, db_path.name)
    cpe_strings = []

    query = f"SELECT cpe FROM cpe_dictionary WHERE product='{package_name}' AND deprecated='0'"

    cursor = db.query_cache(query)
    if not cursor:
        return cpe_strings

    res = cursor.fetchall()

    if not res:
        return cpe_strings

    for cpe in res:
        cpe_strings.append(cpe[0])

    return cpe_strings


def create_cpe_string(cpe: dict) -> str:
    return CpeParser().format_prefix + ":".join(cpe.values())


def find_cves_for_cpe(cpe: str, db_path: pathlib.Path) -> CpeMatchResult:
    db = VulnerabilityDatabase(db_path.parent, db_path.name)
    # db = sqlite3.connect(db_path)

    result = find_cve_with_cpe(cpe, db)

    return result


def find_cve_with_cpe(cpe: str, db: VulnerabilityDatabase) -> CpeMatchResult:
    result = CpeMatchResult(cpe)
    vendor, product, version = result.get_cpe_properties()

    query = f"SELECT DISTINCT cve_number FROM cve_range WHERE product='{product}'"
    second_query = f"AND product='{product}'"
    if vendor != "*":
        query += f" AND vendor='{vendor}'"
        second_query += f" AND vendor='{vendor}'"

    cursor = db.query_cache(query)
    if not cursor:
        return result

    res = cursor.fetchall()

    if not res:
        return result
    for cve in res:
        include = cve_version_included(db, cve[0], product, version, sql_ex=second_query)

        if include:
            vuln = db.get_cve(cve[0])
            result.append_cve(vuln)

    return result


def cve_version_included(db: VulnerabilityDatabase, cve_id, package_name, package_version_str, sql_ex: str):
    cve = cve_id
    package_version = VersionFactory.get_handler(package_name).convert(package_version_str)
    if not sql_ex:
        sql_ex = f"AND product LIKE '{package_name}'"
    query = (
        "SELECT DISTINCT vulnerable, version, versionStartIncluding, versionStartExcluding, versionEndIncluding,"
        f" versionEndExcluding FROM cve_range WHERE cve_number='{cve}' {sql_ex}"
    )
    cursor = db.query_cache(query)

    results = cursor.fetchall()
    for version in results:
        vulnerable = bool(version[0])

        if not vulnerable:
            # The simplest way to deal with this is to ignore the result if it's not a true vulnerability.
            continue

        handler = VersionFactory.get_handler(package_name)
        version_exact = handler.convert(version[1])
        version_starting_including = version[2]
        version_starting_excluding = version[3]
        version_end_including = version[4]
        version_end_excluding = version[5]
        if version_exact == "*" and isinstance(package_version, semantic_version.Version):
            version_start = handler.version_type.coerce("0")
            inc_low = True
            if version_starting_including:
                version_start = handler.convert(version_starting_including)
            elif version_starting_excluding:
                version_start = handler.convert(version_starting_excluding)
                inc_low = False

            version_end = handler.version_type.coerce("10000")
            inc_high = True
            if version_end_including:
                version_end = handler.convert(version_end_including)
            elif version_end_excluding:
                version_end = handler.convert(version_end_excluding)
                inc_high = False

            if isinstance(version_start, str) or isinstance(version_end, str):
                return True
            if inc_low and inc_high and (package_version >= version_start) and (package_version <= version_end):
                return True
            if inc_low and (package_version >= version_start) and (package_version < version_end):
                return True
            if inc_high and (package_version > version_start) and (package_version <= version_end):
                return True
            if (package_version > version_start) and (package_version < version_end):
                return True

        if isinstance(package_version, str) and package_version == "-":
            return True

        if package_version == version_exact:
            return True
    return False


def generate_cpe_list(ext_refs) -> list[str]:
    cpe_list: list[str] = []
    for ref in ext_refs:
        if ref.category is ExternalPackageRefCategory.SECURITY and ref.reference_type.find("/cpe") != -1:
            cpe = ref.locator
            cpe_list.append(cpe)
    return cpe_list


def process_package(package, db_path):
    match = MatchResult(name=package.name, version=package.version)
    unique_cpes = {}
    match_results = {}

    cpes = generate_cpe_list(package.external_references)
    if cpes:
        for cpe in cpes:
            if cpe not in unique_cpes.keys():
                unique_cpes[cpe] = [package]
            else:
                unique_cpes[cpe].append(package)
            match.cpe_list.append(cpe)
    else:
        looked_up_cpes = lookup_cpe_for_package(package.name, db_path)
        new_cpe = CpeParser().parser(f"cpe:2.3:a:*:{package.name}:{package.version}:*:*:*:*:*:*:*")
        if not looked_up_cpes:
            new_cpe_str = create_cpe_string(new_cpe)
            if new_cpe_str not in unique_cpes:
                unique_cpes[new_cpe_str] = [package]
            match.cpe_list.append(new_cpe_str)
        else:
            for cpe in looked_up_cpes:
                parsed_cpe = CpeParser().parser(cpe)
                new_cpe["part"] = parsed_cpe["part"]
                new_cpe["vendor"] = parsed_cpe["vendor"]
                new_cpe_str = create_cpe_string(new_cpe)
                if new_cpe_str not in unique_cpes.keys():
                    unique_cpes[new_cpe_str] = [package]
                else:
                    unique_cpes[new_cpe_str].append(package)
                if new_cpe_str not in match.cpe_list:
                    match.cpe_list.append(new_cpe_str)

    match_results[package.name] = match
    return match_results, unique_cpes

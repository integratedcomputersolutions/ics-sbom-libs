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

from rich import table, print

from beartype.typing import Optional
from cpeparser import CpeParser
from spdx_tools.spdx.model import Document as SPDXDocument
from spdx_tools.spdx.model import CreationInfo as SPDXCreationInfo
from spdx_tools.spdx.model import Package as SPDXPackage
from spdx_tools.spdx.model import Actor as SPDXActor
from spdx_tools.spdx.model import SpdxNoAssertion
from spdx_tools.spdx.model import ActorType as SPDXActorType
from spdx_tools.spdx.model import ExternalPackageRef as SPDXExternalPackageRef
from spdx_tools.spdx.model import ExternalPackageRefCategory as SPDXExternalRefCategory

from ics_sbom_libs.cve_match.package_matching.versionfactory import VersionFactory
from ics_sbom_libs.cve_match.cpe_match_results import CpeMatchResult

from ics_sbom_libs.common.vulnerability import vulnerability_styles
from ics_sbom_libs.cve_fetch.vulnerabilitydatabase import VulnerabilityDatabase


class MatchTableOutput(Enum):
    CvesOnly = 1
    WithoutCvesOnly = 2
    All = 3


def cpe_factory(product: str, version: Optional[str] = None, vendor: Optional[str] = None):
    _vendor = vendor if vendor else "*"
    _version = version if version else "*"

    return f"cpe:2.3:a:{_vendor}:{product}:{_version}:*:*:*:*:*:*:*"


class CveMatcher:
    db_path: pathlib.Path
    _spdx_document: SPDXDocument

    # Results
    result_list: list[MatchResult]

    # Results meta data
    total_package_count: int
    dirty_package_count: int
    clean_package_count: int
    total_cve_count: int

    # Timing meta data
    scanTime: str

    def __init__(self, db_path: pathlib.Path):
        self.db_path = db_path

        self.total_package_count = 0
        self.dirty_package_count = 0
        self.clean_package_count = 0
        self.total_cve_count = 0

        creation_info = SPDXCreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="ICS SBOM Package Search",
            document_namespace="",
            creators=[SPDXActor(SPDXActorType.TOOL, "icsbom")],
            created=datetime.datetime.now(datetime.timezone.utc),
        )
        self._spdx_document = SPDXDocument(creation_info=creation_info)

    @property
    def spdx_document(self):
        return self._spdx_document

    @spdx_document.setter
    def spdx_document(self, document):
        if not isinstance(document, SPDXDocument):
            print("[yellow][b]WARNING:[/b][/yellow] The provided document is not an SPDXDocument.")
            return

        self._spdx_document = document

    def add_package(self, package: str, version: Optional[str] = None, vendor: Optional[str] = None):
        if len(package) == 0:
            print("[red][b]ERROR:[/b] The package name is empty. Not adding to Matcher.[/red]")
            return

        new_package = SPDXPackage(
            name=package,
            spdx_id=f"SPDXRef-{package}",
            version=version,
            supplier=SpdxNoAssertion(),
            download_location=SpdxNoAssertion(),
            description="No Text",
        )

        if vendor:
            new_package.external_references = [
                SPDXExternalPackageRef(
                    SPDXExternalRefCategory.SECURITY,
                    "http://spdx.org/rdf/references/cpe23Type",
                    cpe_factory(package, version, vendor),
                )
            ]

        self._spdx_document.packages.append(new_package)

    def process(self):
        if len(self.spdx_document.packages) == 0:
            print("[red][b]ERROR:[/b] No SPDX Document has no packages[/red]")
            raise RuntimeError("No SPDX Document has no packages")

        self.total_package_count = len(self.spdx_document.packages)
        self.dirty_package_count = 0
        self.clean_package_count = 0
        self.total_cve_count = 0

        self.result_list = process(self.spdx_document, self.db_path)
        self.scanTime = str(datetime.datetime.now(datetime.timezone.utc)).replace(" ", "T")[:-7] + "Z"

        for result in self.result_list:
            if result.cve_list:
                self.dirty_package_count += 1
                self.total_cve_count += len(result.cve_list)
            else:
                self.clean_package_count += 1

    def create_match_table(self, table_output: MatchTableOutput = MatchTableOutput.All):
        match_table = table.Table(title="CVE Results", row_styles=["dim", ""], expand=True)
        match_table.add_column(header="Package", style="green")
        match_table.add_column(header="Version", style="magenta")
        match_table.add_column(header="CVE Count", style="blue")
        match_table.add_column(header="None", style=vulnerability_styles["NONE"].style)
        match_table.add_column(header="Low", style=vulnerability_styles["LOW"].style)
        match_table.add_column(header="Medium", style=vulnerability_styles["MEDIUM"].style)
        match_table.add_column(header="High", style=vulnerability_styles["HIGH"].style)
        match_table.add_column(header="Critical", style=vulnerability_styles["CRITICAL"].style)
        match_table.add_column(header="CVEs")

        vuln_info_counts = {"Total": 0, "NONE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for result in self.result_list:
            vuln_info = result.get_severity_info()
            if result.cve_list and table_output != MatchTableOutput.WithoutCvesOnly:
                sorted_cves = sorted(result.cve_list)
                formated_cves = " ".join(
                    f"{vulnerability_styles[cve.severity].indicator}{cve.generate_cve_link_text()}"
                    for cve in sorted_cves
                )
                match_table.add_row(
                    f"{result.name}",
                    f"{result.version}",
                    f"{len(result.cve_list)}",
                    f'{vuln_info["NONE"]}',
                    f'{vuln_info["LOW"]}',
                    f'{vuln_info["MEDIUM"]}',
                    f'{vuln_info["HIGH"]}',
                    f'{vuln_info["CRITICAL"]}',
                    f"{formated_cves}",
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
        for result in self.result_list:
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
                executor.submit(process_spdx_package, package, db_path): package for package in spdx_document.packages
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
            result, unique_cpes_partial = process_spdx_package(package, db_path)
            match_results.update(result)
            for cpe, packages in unique_cpes_partial.items():
                if cpe not in unique_cpes:
                    unique_cpes[cpe] = packages
                else:
                    unique_cpes[cpe].extend(packages)
            package_pbar.update()

    pbar = tqdm(
        total=len(unique_cpes),
        desc="Checking CPEs for Known Issues",
        unit="cpes",
        mininterval=0,
        miniters=1,
        position=0,
        leave=True,
    )
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

    try:
        if not res:
            return result
        for cve in res:
            include = cve_version_included(db, cve[0], product, version, sql_ex=second_query)

            if include:
                vuln = db.get_cve(cve[0])
                result.append_cve(vuln)

    except ValueError as vError:
        print(
            f"[red][b]ERROR:[/b] While processing {product} by {vendor} with version {version} had error:"
            f" {vError}[/red]"
        )

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
        if ref.category is SPDXExternalRefCategory.SECURITY and ref.reference_type.find("/cpe") != -1:
            cpe = ref.locator
            cpe_list.append(cpe)
    return cpe_list


def process_spdx_package(spdx_package, db_path):
    match = MatchResult(name=spdx_package.name, version=spdx_package.version)
    unique_cpes = {}
    match_results = {}

    cpes = generate_cpe_list(spdx_package.external_references)
    if cpes:
        for cpe in cpes:
            if cpe not in unique_cpes.keys():
                unique_cpes[cpe] = [spdx_package]
            else:
                unique_cpes[cpe].append(spdx_package)
            match.cpe_list.append(cpe)
    else:
        looked_up_cpes = lookup_cpe_for_package(spdx_package.name, db_path)
        new_cpe = CpeParser().parser(cpe_factory(spdx_package.name, spdx_package.version))
        if not looked_up_cpes:
            new_cpe_str = create_cpe_string(new_cpe)
            if new_cpe_str not in unique_cpes:
                unique_cpes[new_cpe_str] = [spdx_package]
            match.cpe_list.append(new_cpe_str)
        else:
            for cpe in looked_up_cpes:
                parsed_cpe = CpeParser().parser(cpe)
                new_cpe["part"] = parsed_cpe["part"]
                new_cpe["vendor"] = parsed_cpe["vendor"]
                new_cpe_str = create_cpe_string(new_cpe)
                if new_cpe_str not in unique_cpes.keys():
                    unique_cpes[new_cpe_str] = [spdx_package]
                else:
                    unique_cpes[new_cpe_str].append(spdx_package)
                if new_cpe_str not in match.cpe_list:
                    match.cpe_list.append(new_cpe_str)

    match_results[spdx_package.name] = match
    return match_results, unique_cpes

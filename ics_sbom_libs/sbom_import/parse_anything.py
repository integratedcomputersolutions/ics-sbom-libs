# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>
# SPDX-FileContributor: Chris Rizzitello <crizzitello@ics.com>

import copy
import logging
import re
import json

import pathlib
import tarfile
import argparse

from cpeparser import CpeParser
from tqdm import tqdm
from datetime import datetime
from spdx_tools.spdx.formats import file_name_to_format, FileFormat
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.parser.error import SPDXParsingError

from spdx_tools.spdx.model import Document as SPDXDocument, SpdxNone, ExternalPackageRef, ExternalPackageRefCategory
from spdx_tools.spdx.model import CreationInfo as SPDXCreationInfo
from spdx_tools.spdx.model import Actor as SPDXActor
from spdx_tools.spdx.model import ActorType as SPDXActorType

from ics_sbom_libs.sbom_import.spdx_tag_value.parse import parse_from_tag_value_file
from ics_sbom_libs.sbom_import.spdx_json.parse import parse_from_json_file, parse_from_json

log = logging.getLogger(__name__)


class FilterList:
    def __init__(self):

        self._pkg_substitution = {
            "qtbase": {"duplicate": {"rename": "qt"}, "sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtsvg": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtdeclarative": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtgraphicaleffects": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtmultimedia": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtquickcontrols": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtquickcontrols2": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtserialport": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qttools": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtvirtualkeyboard": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtwebsockets": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "qtxmlpatterns": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
            "flex": {"add_cpe": {"vendor": "westes", "product": "<name>", "version": "<version>"}},
            "dbus": {"duplicate": {"rename": "libdbus", "sub_cpe": {"product": {"orig": "dbus", "new": "<name>"}}}},
            "flac": {
                "sub_cpe": {
                    "vendor": {"orig": "*", "new": "flac_project"},
                    "product": {"orig": "libflac", "new": "<name>"},
                }
            },
            "bzip2": {"add_cpe": {"vendor": "bzip", "product": "compress-raw-bzip2", "version": "<version>"}},
            "libflac++6": {"add_cpe": {"vendor": "flac_project", "product": "flac", "version": "<version>"}},
            "libflac8": {"add_cpe": {"vendor": "flac_project", "product": "flac", "version": "<version>"}},
            "curl": {
                "duplicate": {"rename": "libcurl", "rem_cpe": {"product": "curl"}},
                "rem_cpe": {"product": "libcurl"},
            },
            "libcurl3": {"rename": "libcurl"},
            "libcurl4": {"rename": "libcurl"},
            "expat": {
                "duplicate": {"rename": "libexpat", "rem_cpe": {"product": "expat"}},
                "rem_cpe": {"product": "libexpat"},
            },
            "file": {"add_cpe": {"vendor": "file_project", "product": "<name>", "version": "<version>"}},
            "perl": {"add_cpe": {"vendor": "perl", "product": "<name>", "version": "<version>"}},
        }

        self._exclusion_list = [
            "-doc",
            "-dev",
            "-dbg",
            "locale",
            "-ptest",
            "-tests",
            "-examples",
            "-mkspecs",
            "-staticdev",
            "qttranslations",
            "packagegroup",
            "glibc-gconv",
            "glibc-charmap",
            "tzdata-",
            "-completion",
            "-data",
            "-src",
            "-native",
            "-cross-",
        ]

    @property
    def exclusions(self):
        return self._exclusion_list

    @exclusions.setter
    def exclusions(self, new_list: list):
        if not new_list:
            return

        # removes any duplicates.
        self._exclusion_list = list(set(new_list))

    @property
    def substitutions(self):
        return self._pkg_substitution

    @substitutions.setter
    def substitutions(self, new_substitutions: dict):
        if not new_substitutions:
            return

        self._pkg_substitution = new_substitutions

    def add_exclusion(self, exclude: str):
        if exclude not in self._exclusion_list:
            self._exclusion_list.append(exclude)

    def remove_exclusion(self, remove: str):
        if remove in self._exclusion_list:
            self._exclusion_list.remove(remove)

    def set_filters_from_file(self, list_file_path: pathlib.Path):
        if not list_file_path or not list_file_path.exists():
            return

        with open(list_file_path, "r") as new_list_file:
            filters = json.load(new_list_file)

            if "exclusions" in filters.keys():
                self.exclusions = filters["exclusions"]

            if "substitutions" in filters.keys():
                self.substitutions = filters["substitutions"]

    def compile_exclusions(self):
        return re.compile("|".join(self._exclusion_list))

    def compile_substitutions(self):
        return re.compile("|".join(self._pkg_substitution.keys()))


class FilteredParser:

    def __init__(self):
        self._filter = FilterList()
        self._encoding = "utf-8"
        self._tar_dir_pattern = ""

    @property
    def encoding(self):
        return self._encoding

    @encoding.setter
    def encoding(self, value: str):
        if not value:
            return

        if value != "utf-8":
            log.warning(
                "It's recommended to use the UTF-8 encoding for any SPDX file. "
                "Consider changing the encoding of the file."
            )

        self._encoding = value

    @property
    def filter_list(self):
        return self._filter

    @filter_list.setter
    def filter_list(self, new_list: FilterList):
        if not new_list:
            return

        self._filter = new_list

    @property
    def tar_dir_pattern(self):
        return self._tar_dir_pattern

    @tar_dir_pattern.setter
    def tar_dir_pattern(self, new_pattern: str):
        if not new_pattern:
            return

        self._tar_dir_pattern = new_pattern

    @staticmethod
    def setup_args(parser: argparse.ArgumentParser):
        if not parser:
            return

        parser.add_argument(
            "--filter_file",
            type=pathlib.Path,
            default="",
            help="Sets the up the filtering for substitutions and exclusions to the " "contents of the file",
        )

        parser.add_argument(
            "--write_filters",
            type=pathlib.Path,
            default=None,
            help="Writes a filter file that contains the default filters",
        )

        parser.add_argument(
            "-t",
            "--tar_dir_pattern",
            type=str,
            help="sets a dir name pattern to search for in the tar file if a tar file is given "
            'as the input file. ["recipes"|"packages"]',
        )

    def process_args(self, args):
        if not args:
            return

        if args.filter_file.is_file():
            self.filter_list.set_filters_from_file(args.filter_file)

        if args.tar_dir_pattern:
            self._tar_dir_pattern = args.tar_dir_pattern

        if args.write_filters is not None:
            f = open(args.write_filters, "w")
            fout = '{\n  "substitutions": %s,LAST_SUB\n  "exclusions": %sLAST_EXCLUDE\n}' % (
                json.dumps(self.filter_list.substitutions, indent=4),
                json.dumps(self.filter_list.exclusions, indent=4),
            )
            fout = fout.replace("},LAST_SUB", "  },")
            fout = fout.replace("]LAST_EXCLUDE", "  ]")
            f.write(fout)
            f.close()

    def parse(self, sbom_name: pathlib.Path):
        doc: SPDXDocument | None = None

        if sbom_name.is_file() and tarfile.is_tarfile(sbom_name):
            doc = self._parse_tar(sbom_name)

        elif sbom_name.is_file():
            doc = self._parse_file(sbom_name)

        elif sbom_name.is_dir():
            doc = self._parse_dir(sbom_name)

        if not doc:
            return None

        def handle_substitutions(sub_package, package_substitutions):
            return_packages = [sub_package]
            for sub_command in package_substitutions.keys():
                if sub_command == "remove":
                    return []

                if sub_command == "rename":
                    sub_package.name = package_substitutions[sub_command]

                elif sub_command == "duplicate":
                    new_package = copy.deepcopy(sub_package)
                    return_packages += handle_substitutions(new_package, package_substitutions[sub_command])

                elif sub_command == "sub_cpe":
                    for ref in sub_package.external_references:
                        if (
                            ref.category is ExternalPackageRefCategory.SECURITY
                            and ref.reference_type.find("/cpe") != -1
                        ):
                            cpe = CpeParser().parser(ref.locator)
                            for part in package_substitutions[sub_command]:
                                if part == "version" and package_substitutions[sub_command][part]["orig"] == "*":
                                    if package_substitutions[sub_command][part]["new"] == "<version>":
                                        cpe[part] = sub_package.version
                                    else:
                                        cpe[part] = package_substitutions[sub_command][part]["new"]
                                if cpe[part] == package_substitutions[sub_command][part]["orig"]:
                                    if package_substitutions[sub_command][part]["new"] == "<name>":
                                        cpe[part] = sub_package.name
                                    else:
                                        cpe[part] = package_substitutions[sub_command][part]["new"]
                            ref.locator = CpeParser().format_prefix + ":".join(cpe.values())

                elif sub_command == "rem_cpe":
                    remove_refs = []
                    for ref in sub_package.external_references:
                        if (
                            ref.category is ExternalPackageRefCategory.SECURITY
                            and ref.reference_type.find("/cpe") != -1
                        ):
                            cpe = CpeParser().parser(ref.locator)
                            for part in package_substitutions[sub_command]:
                                if cpe[part] == package_substitutions[sub_command][part]:
                                    remove_refs.append(ref)

                    for ref in remove_refs:
                        sub_package.external_references.remove(ref)

                elif sub_command == "add_cpe":
                    new_cpe = CpeParser().parser("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")
                    for part in package_substitutions[sub_command]:
                        if package_substitutions[sub_command][part] == "<version>":
                            new_cpe[part] = sub_package.version
                        elif package_substitutions[sub_command][part] == "<name>":
                            new_cpe[part] = sub_package.name
                        else:
                            new_cpe[part] = package_substitutions[sub_command][part]
                    ref = ExternalPackageRef(
                        category=ExternalPackageRefCategory.SECURITY,
                        reference_type="http://spdx.org/rdf/references/cpe23Type",
                        locator=CpeParser().format_prefix + ":".join(new_cpe.values()),
                    )
                    sub_package.external_references.append(ref)

            return return_packages

        exclusions = self._filter.compile_exclusions()
        substitutions = list(self._filter.substitutions.keys())

        packages = sorted(doc.packages, key=lambda pkg: pkg.name)
        doc.packages.clear()
        for package in packages:
            added_packages = []
            if exclusions.search(package.name):
                continue

            if package.name in substitutions:
                added_packages = handle_substitutions(package, self._filter.substitutions[package.name])
            else:
                added_packages = [package]

            doc.packages += added_packages

        doc.packages = sorted(doc.packages, key=lambda pkg: pkg.name)
        return doc

    def _parse_file(self, sbom_file_name: pathlib.Path):
        input_format = file_name_to_format(str(sbom_file_name))

        try:
            if input_format == FileFormat.TAG_VALUE:
                return parse_from_tag_value_file(str(sbom_file_name), self.encoding)
            elif input_format == FileFormat.JSON:
                return parse_from_json_file(str(sbom_file_name), self.encoding)
            else:
                # Use the more general parser
                return spdx_parse_file(str(sbom_file_name), self.encoding)
        except SPDXParsingError as e:
            messages = e.messages
            logging.warning(f"Error processing {sbom_file_name.name}: {messages[0]}")

        return None

    def _parse_dir(self, sbom_dir_name: pathlib.Path):
        doc: SPDXDocument | None = None

        if not sbom_dir_name or not sbom_dir_name.is_dir():
            logging.warning(f"Given path, {sbom_dir_name}, does not exist or is not a directory.")
            return doc

        actor = SPDXActor(actor_type=SPDXActorType.ORGANIZATION, name="ics")
        doc_ci = SPDXCreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef_DOCUMENT",
            name="no-name",
            document_namespace="com.ics.no-name",
            created=datetime.now(),
            creators=[actor],
        )
        doc = SPDXDocument(doc_ci)
        name_filter = self._filter.compile_exclusions()

        files = [f for f in sbom_dir_name.iterdir()]
        for file in (pbar := tqdm(files, desc="Processing packages", unit="package")):
            if name_filter.search(file.name):
                continue

            pbar.set_postfix_str(str(file.name))
            file_doc = self._parse_file(file)
            doc.packages += file_doc.packages
            doc.files += file_doc.files
            doc.snippets += file_doc.snippets
            doc.annotations += file_doc.annotations
            doc.relationships += file_doc.relationships
            doc.extracted_licensing_info += file_doc.extracted_licensing_info

        return doc

    def _parse_tar(self, sbom_tar_name: pathlib.Path):
        doc: SPDXDocument | None = None

        if not sbom_tar_name or not sbom_tar_name.is_file():
            logging.warning(f"Given path, {sbom_tar_name}, does not exist.")
            return doc

        try:
            tf = tarfile.open(sbom_tar_name)
        except tarfile.ReadError:
            logging.warning(f"Failed to read, {sbom_tar_name}")
            return doc

        actor = SPDXActor(actor_type=SPDXActorType.ORGANIZATION, name="ics")
        doc_ci = SPDXCreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef_DOCUMENT",
            name="no-name",
            document_namespace="com.ics.no-name",
            created=datetime.now(),
            creators=[actor],
        )
        doc = SPDXDocument(doc_ci)
        name_filter = self._filter.compile_exclusions()

        pattern_dir = []
        if self._tar_dir_pattern:
            pattern_dir = [
                member.name for member in tf.getmembers() if member.isdir() and self._tar_dir_pattern in member.name
            ]

        files: list
        if pattern_dir:
            files = [f for f in tf.getmembers() if f.name.startswith(pattern_dir[0]) and not f.isdir()]
        else:
            files = [f for f in tf.getmembers() if not f.isdir() and ".spdx" in f.name]

        for file in (pbar := tqdm(files, desc="Processing packages", unit="package")):
            if name_filter.search(file.name):
                continue

            pname = pathlib.Path(file.name)
            if pname.name.startswith("."):
                continue

            pbar.set_postfix_str(pname.name)
            contents = tf.extractfile(file)
            file_doc = parse_from_json(contents)
            doc.packages += file_doc.packages
            doc.files += file_doc.files
            doc.snippets += file_doc.snippets
            doc.annotations += file_doc.annotations
            doc.relationships += file_doc.relationships
            doc.extracted_licensing_info += file_doc.extracted_licensing_info

        return doc


def parse_anything(sbom_name: pathlib.Path, encoding: str = "utf-8"):
    """
    Uses the default FilterParser to process either a SBoM file or a directory of SBoM files.

    :param sbom_name:  The name of the SBoM file or SBoM files directory
    :param encoding: Text encoding of the file. (Default: "utf-8")
    :return: SPDX Document
    """
    if encoding != "utf-8":
        logging.warning(
            "It's recommended to use the UTF-8 encoding for any SPDX file. Consider changing the encoding of the file."
        )

    if sbom_name == pathlib.Path() or not (sbom_name.is_dir() or sbom_name.is_file()):
        logging.warning(f"Given path, {sbom_name}, does not exist or is not a directory.")
        return None

    parser = FilteredParser()
    parser.encoding = encoding

    return parser.parse(sbom_name)


def print_package_table(doc: SPDXDocument):
    """
    Prints a table of the packages from the given doc

    :param doc:  The SBoM document
    """
    name_width = 30
    version_width = 30
    license_width = 20
    vendors_width = 55
    related_width = 55

    # Get the max width of each column
    for package in doc.packages:
        package_license = (
            package.license_declared.get_literals()[0].key
            if package.license_declared is not None and not isinstance(package.license_declared, SpdxNone)
            else ""
        )
        name_width = name_width if len(package.name) < name_width else len(package.name)
        version_width = version_width if len(package.version) < version_width else len(package.version)
        license_width = license_width if len(package_license) < license_width else len(package_license)

    # Set the format
    table_format = " ".join(
        [
            "\t{:>5}",
            "{:<" + f"{name_width}" + "}",
            "{:<" + f"{version_width}" + "}",
            "{:<" + f"{license_width}" + "}",
            "{:<" + f"{vendors_width}" + "}",
            "{:<" + f"{related_width}" + "}",
        ]
    )

    # Print Header
    print("Packages Table:")
    print(table_format.format("     ", "Package Name", "Version", "License", "Vendors", "Related"))

    # Print Table
    package_index = 1
    for package in doc.packages:
        package_license = (
            package.license_declared.get_literals()[0].key
            if package.license_declared is not None and not isinstance(package.license_declared, SpdxNone)
            else ""
        )
        vendors = []
        related = []
        for refs in package.external_references:
            cpe_str = refs.locator
            cpe_parts = cpe_str.split(":")
            if cpe_parts[3] not in vendors:
                vendors.append(cpe_parts[3])
            if cpe_parts[4] not in related and cpe_parts[4] != doc.creation_info.name:
                related.append(cpe_parts[4])

        print(
            table_format.format(
                package_index, package.name, package.version, package_license, ", ".join(vendors), ", ".join(related)
            )
        )
        package_index += 1

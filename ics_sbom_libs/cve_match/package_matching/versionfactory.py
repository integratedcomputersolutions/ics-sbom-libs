# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

from ics_sbom_libs.cve_match.package_matching import VersionHandler


class VersionFactory:
    _instance = None
    _handlers: dict = {}

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(VersionFactory, cls).__new__(cls)

        return cls._instance

    def _add_handler(self, handler_type):
        if not issubclass(handler_type, VersionHandler):
            return

        package_name = handler_type().package
        if package_name not in self._handlers.keys():
            self._handlers[package_name] = handler_type

    @staticmethod
    def get_handler(package_name: str) -> VersionHandler:
        factory = VersionFactory()
        return (
            factory._handlers[package_name]()
            if package_name in factory._handlers.keys()
            else factory._handlers["default"]()
        )

    @staticmethod
    def add_package_handler(handler_type):
        factory = VersionFactory()
        factory._add_handler(handler_type)

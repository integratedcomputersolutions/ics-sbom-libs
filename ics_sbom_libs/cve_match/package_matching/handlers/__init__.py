# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Ics inc.

from .default import DefaultVersionHandler
from .openssh import OpenSSHVersionHandler
from .openssl import OpenSSLVersionHandler
from .linux_kernel import LinuxKernelVersionHandler

from ics_sbom_libs.cve_match.package_matching.versionfactory import VersionFactory


__all__ = ["default", "openssh", "openssl", "linux_kernel"]

VersionFactory.add_package_handler(DefaultVersionHandler)
VersionFactory.add_package_handler(OpenSSHVersionHandler)
VersionFactory.add_package_handler(OpenSSLVersionHandler)
VersionFactory.add_package_handler(LinuxKernelVersionHandler)

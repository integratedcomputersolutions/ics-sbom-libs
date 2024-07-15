# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import semantic_version


class BuildVersion(semantic_version.Version):

    def __init__(
        self, version_string=None, major=None, minor=None, patch=None, prerelease=None, build=None, partial=False
    ):
        super(BuildVersion, self).__init__(version_string, major, minor, patch, prerelease, build, partial)

        # _cmp_precedence_key is used for semver-precedence comparison
        self._cmp_precedence_key = self._build_precedence_key(with_build=True)

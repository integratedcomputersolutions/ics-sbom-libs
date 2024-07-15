# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>

import unittest
from src.ics_sbom_libs.common.dbproperties import DBProperties


class DBPropertiesTestCase(unittest.TestCase):
    def test_raw_init(self):
        props = DBProperties()

        self.assertEqual(props.database_type, "")
        self.assertEqual(props.database_name, "")
        self.assertEqual(props.database_user, "")
        self.assertEqual(props.database_password, "")
        self.assertEqual(props.host_name, "localhost")
        self.assertEqual(props.host_port, "5432")

    def test_connection_string(self):
        props = DBProperties(
            database_type="postgresql", database_name="testdb", user_name="postgres", password="postgres123"
        )

        self.assertEqual(props.database_type, "postgresql")
        self.assertEqual(props.database_name, "testdb")
        self.assertEqual(props.database_user, "postgres")
        self.assertEqual(props.database_password, "postgres123")
        self.assertEqual(props.host_name, "localhost")
        self.assertEqual(props.host_port, "5432")

        self.assertEqual(props.connection_string, "postgresql://postgres:postgres123@localhost:5432/testdb")


if __name__ == "__main__":
    unittest.main()

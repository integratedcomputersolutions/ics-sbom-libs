# SPDX-License-Identifier: LGPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>


class DBProperties:
    def __init__(
        self,
        database_type: str = "",
        database_name: str = "",
        user_name: str = "",
        password: str = "",
        host_name="localhost",
        host_port="5432",
    ):
        self._connection_string: str = ""

        self._db_type = database_type  # 'postgresql'
        self._db_name = database_name  # 'cve_database'
        self._db_user = user_name  # 'postgres'
        self._db_pass = password  # 'postgres123'
        self._db_host = host_name  # 'localhost'
        self._db_port = host_port  # '5432'

        self._update_connection_string()

    @property
    def database_type(self):
        return self._db_type

    @database_type.setter
    def database_type(self, db_type: str = ""):
        if len(db_type) == 0:
            return

        self._db_type = db_type
        self._update_connection_string()

    @property
    def database_name(self):
        return self._db_name

    @database_name.setter
    def database_name(self, db_name: str = ""):
        if len(db_name) == 0:
            return

        self._db_name = db_name
        self._update_connection_string()

    @property
    def database_user(self):
        return self._db_user

    @database_user.setter
    def database_user(self, db_user: str = ""):
        if len(db_user) == 0:
            return

        self._db_user = db_user
        self._update_connection_string()

    @property
    def database_password(self):
        return self._db_pass

    @database_password.setter
    def database_password(self, db_password: str = ""):
        if len(db_password) == 0:
            return

        self._db_pass = db_password
        self._update_connection_string()

    @property
    def host_name(self):
        return self._db_host

    @host_name.setter
    def host_name(self, db_host: str = ""):
        if len(db_host) == 0:
            return

        self._db_host = db_host
        self._update_connection_string()

    @property
    def host_port(self):
        return self._db_port

    @host_port.setter
    def host_port(self, db_port: str = ""):
        if len(db_port) == 0:
            return

        self._db_port = db_port
        self._update_connection_string()

    @property
    def connection_string(self):
        self._update_connection_string()
        # Connect to the database
        return self._connection_string

    def _update_connection_string(self):
        self._connection_string = (
            f"{self._db_type}://{self._db_user}:{self._db_pass}@{self._db_host}:{self._db_port}/{self._db_name}"
        )

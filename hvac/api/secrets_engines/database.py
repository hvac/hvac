#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Database methods module."""
from hvac.api.vault_api_base import VaultApiBase


class Database(VaultApiBase):
    """Database Secrets Engine (API).

    Reference: https://www.vaultproject.io/api/secret/databases/index.html
    """

    def configure(self, name, plugin_name, verify_connection=True, allowed_roles=[], root_rotation_statements=[],
                  *args, **kwargs):
        """This endpoint configures the connection string used to communicate with the desired database.
        In addition to the parameters listed here, each Database plugin has additional,
        database plugin specific, parameters for this endpoint.
        Please read the HTTP API for the plugin you'd wish to configure to see the full list of additional parameters.

        :param name: Specifies the name for this database connection. This is specified as part of the URL.
        :type name: str | unicode
        :param plugin_name: Specifies the name of the plugin to use for this connection.
        :type plugin_name: str | unicode
        :param verify_connection: Specifies if the connection is verified during initial configuration.
        :type verify_connection: bool
        :param allowed_roles: List of the roles allowed to use this connection. Defaults to empty (no roles),
        if contains a "*" any role can use this connection.
        :type allowed_roles: list
        :param root_rotation_statements: Specifies the database statements to be executed to rotate
        the root user's credentials.
        :type root_rotation_statements: list
        :return: The response of the request.
        :rtype: requests.Response
        """
        params = {
          "plugin_name": plugin_name,
          "allowed_roles": allowed_roles,
          "verify_connection": verify_connection,
          "root_rotation_statements": root_rotation_statements
        }

        params.update(kwargs)

        api_path = "/v1/database/config/{}".format(name)
        return self._adapter.post(
            url=api_path,
            json=params,
        ).json()

    def rotate_root_credentials(self, name):
        """This endpoint is used to rotate the root superuser credentials stored for the database connection.
        This user must have permissions to update its own password.

        :param name: Specifies the name of the connection to rotate.
        :type name: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = "/v1/database/rotate-root/{}".format(name)
        return self._adapter.post(
            url=api_path,
        ).json()

    def read_connection(self, name):
        """This endpoint returns the configuration settings for a connection.

        :param name: Specifies the name of the connection to read.
        :type name: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """

        api_path = "/v1/database/config/{}".format(name)

        return self._adapter.get(
            url=api_path,
        ).json()

    def list_connections(self):
        """This endpoint returns a list of available connections.

        :return: The response of the request.
        :rtype: requests.Response
        """

        api_path = "/v1/database/config"
        return self._adapter.list(
            url=api_path,
        ).json()

    def delete_connection(self, name):
        """This endpoint deletes a connection.


        :param name: Specifies the name of the connection to delete.
        :type name: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = "/v1/database/config/{}".format(name)
        return self._adapter.delete(
            url=api_path,
        ).json()

    def reset_connection(self, name):
        """This endpoint closes a connection and it's underlying plugin and
        restarts it with the configuration stored in the barrier.

        :param name: Specifies the name of the connection to reset.
        :type name: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = "/v1/database/reset/{}".format(name)
        return self._adapter.post(
            url=api_path,
        ).json()

    def create_role(self, name, db_name, creation_statements, default_ttl=0, max_ttl=0,
                    revocation_statements=list(), rollback_statements=list(), renew_statements=list()):
        """This endpoint creates or updates a role definition.

        :param name: Specifies the database role to manage.
        :type name: str | unicode
        :param db_name: Specifies the database role to manage.
        :type db_name: str | unicode
        :param creation_statements: Specifies the database role to manage.
        :type creation_statements: str | unicode
        :param default_ttl: Specifies the database role to manage.
        :type default_ttl: int
        :param max_ttl: Specifies the database role to manage.
        :type max_ttl: int
        :param revocation_statements: Specifies the database role to manage.
        :type revocation_statements: list
        :param rollback_statements: Specifies the database role to manage.
        :type rollback_statements: list
        :param renew_statements: Specifies the database role to manage.
        :type renew_statements: list
        :return: The response of the request.
        :rtype: requests.Response
        """

        params = {
            "db_name": db_name,
            "creation_statements": creation_statements,
            "default_ttl": default_ttl,
            "max_ttl": max_ttl,
            "revocation_statements": revocation_statements,
            "rollback_statements": rollback_statements,
            "renew_statements": renew_statements
        }

        api_path = "/v1/database/roles/{}".format(name)
        return self._adapter.post(
            url=api_path,
            params=params
        ).json()

    def read_role(self, name):
        """This endpoint queries the role definition.

        :param name: Specifies the name of the role to read.
        :type name: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """

        api_path = "/v1/database/roles/{}".format(name)

        return self._adapter.get(
            url=api_path,
        ).json()

    def list_roles(self):
        """This endpoint returns a list of available roles.

        :return: The response of the request.
        :rtype: requests.Response
        """

        api_path = "/v1/database/roles"
        return self._adapter.list(
            url=api_path,
        ).json()

    def delete_role(self, name):
        """This endpoint deletes the role definition.

        :param name: Specifies the name of the role to delete.
        :type name: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = "/v1/database/roles/{}".format(name)
        return self._adapter.delete(
            url=api_path,
        ).json()

    def generate_credentials(self, name):
        """This endpoint generates a new set of dynamic credentials based on the named role.

        :param name: Specifies the name of the role to create credentials against
        :type name: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """

        api_path = "/v1/database/creds/{}".format(name)

        return self._adapter.get(
            url=api_path,
        ).json()

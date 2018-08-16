#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Gcp methods module."""
from hvac.api.vault_api_base import VaultApiBase


DEFAULT_MOUNT_POINT = ''


class Gcp(VaultApiBase):
    """Google Cloud Auth Method (API).

    Reference: https://www.vaultproject.io/api/auth/gcp/index.html
    """

    def configure(self, credentials="", google_certs_endpoint="https://www.googleapis.com/oauth2/v3/certs", mount_point=DEFAULT_MOUNT_POINT):
        """
        Configures the credentials required for the plugin to perform API calls
        to Google Cloud. These credentials will be used to query the status of IAM
        entities and get service account or other Google public certificates
        to confirm signed JWTs passed in during login.

        Supported methods:
            POST: /auth/gcp/config. Produces: 204 (empty body)


        :param credentials:
        :type credentials: str | unicode
        :param google_certs_endpoint: The Google OAuth2 endpoint
            from which to obtain public certificates. This is used for testing and should
            generally not be set by end users.
        :type google_certs_endpoint: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the configure request.
        :rtype: requests.Response
        """
        params = {
            'credentials': credentials,
            'google_certs_endpoint': google_certs_endpoint,
        }
        api_path = '/v1/auth/gcp/config'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_config(self, name, type, project_id, bound_service_accounts, ttl="", max_ttl="", period="", policies=[default], mount_point=DEFAULT_MOUNT_POINT):
        """
        Returns the configuration, if any, including credentials.

        Supported methods:
            GET: /auth/gcp/config. Produces: 200 application/json


        :param name: The name of the role.
        :type name: str | unicode
        :param type: The type of this role. Certain fields
            correspond to specific roles and will be rejected otherwise. Please see below
            for more information.
        :type type: str | unicode
        :param project_id: The GCP project ID. Only entities belonging to this
            project can authenticate with this role.
        :type project_id: str | unicode
        :param bound_service_accounts: all service accounts are allowed (role will still be bound by project).
            Will be inferred from service account used to issue metadata token for GCE
            instances.
        :type bound_service_accounts: array
        :param ttl: The TTL period of tokens issued using this role. This
            can be specified as an integer number of seconds or as a duration value like
            "5m".
        :type ttl: str | unicode
        :param max_ttl: The maximum allowed lifetime of tokens issued in
            seconds using this role. This can be specified as an integer number of seconds
            or as a duration value like "5m".
        :type max_ttl: str | unicode
        :param period: If set, indicates that the token generated using
            this role should never expire. The token should be renewed within the duration
            specified by this value. At each renewal, the token's TTL will be set to the
            value of this parameter. This can be specified as an integer number of seconds
            or as a duration value like "5m".
        :type period: str | unicode
        :param policies: The list of policies to be set on tokens
            issued using this role.
        :type policies: array
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_config request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'type': type,
            'project_id': project_id,
            'bound_service_accounts': bound_service_accounts,
            'ttl': ttl,
            'max_ttl': max_ttl,
            'period': period,
            'policies': policies,
        }
        api_path = '/v1/auth/gcp/config'.format(mount_point=mount_point)
        return self._adapter.get(
            url=api_path,
            json=params,
        )

    def delete_config(self, name, type, project_id, bound_service_accounts, ttl="", max_ttl="", period="", policies=[default], mount_point=DEFAULT_MOUNT_POINT):
        """
        Deletes all GCP configuration data. This operation is idempotent.

        Supported methods:
            DELETE: /auth/gcp/config. Produces: 204 (empty body)


        :param name: The name of the role.
        :type name: str | unicode
        :param type: The type of this role. Certain fields
            correspond to specific roles and will be rejected otherwise. Please see below
            for more information.
        :type type: str | unicode
        :param project_id: The GCP project ID. Only entities belonging to this
            project can authenticate with this role.
        :type project_id: str | unicode
        :param bound_service_accounts: all service accounts are allowed (role will still be bound by project).
            Will be inferred from service account used to issue metadata token for GCE
            instances.
        :type bound_service_accounts: array
        :param ttl: The TTL period of tokens issued using this role. This
            can be specified as an integer number of seconds or as a duration value like
            "5m".
        :type ttl: str | unicode
        :param max_ttl: The maximum allowed lifetime of tokens issued in
            seconds using this role. This can be specified as an integer number of seconds
            or as a duration value like "5m".
        :type max_ttl: str | unicode
        :param period: If set, indicates that the token generated using
            this role should never expire. The token should be renewed within the duration
            specified by this value. At each renewal, the token's TTL will be set to the
            value of this parameter. This can be specified as an integer number of seconds
            or as a duration value like "5m".
        :type period: str | unicode
        :param policies: The list of policies to be set on tokens
            issued using this role.
        :type policies: array
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_config request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'type': type,
            'project_id': project_id,
            'bound_service_accounts': bound_service_accounts,
            'ttl': ttl,
            'max_ttl': max_ttl,
            'period': period,
            'policies': policies,
        }
        api_path = '/v1/auth/gcp/config'.format(mount_point=mount_point)
        return self._adapter.delete(
            url=api_path,
            json=params,
        )

    def create_role(self, name, type, project_id, bound_service_accounts, ttl="", max_ttl="", period="", policies=[default], mount_point=DEFAULT_MOUNT_POINT):
        """
        Registers a role in the method. Role types have specific entities
        that can perform login operations against this endpoint. Constraints specific
        to the role type must be set on the role. These are applied to the authenticated
        entities attempting to login.

        Supported methods:
            POST: /auth/gcp/role/:name. Produces: 204 (empty body)


        :param name: The name of the role.
        :type name: str | unicode
        :param type: The type of this role. Certain fields
            correspond to specific roles and will be rejected otherwise. Please see below
            for more information.
        :type type: str | unicode
        :param project_id: The GCP project ID. Only entities belonging to this
            project can authenticate with this role.
        :type project_id: str | unicode
        :param bound_service_accounts: all service accounts are allowed (role will still be bound by project).
            Will be inferred from service account used to issue metadata token for GCE
            instances.
        :type bound_service_accounts: array
        :param ttl: The TTL period of tokens issued using this role. This
            can be specified as an integer number of seconds or as a duration value like
            "5m".
        :type ttl: str | unicode
        :param max_ttl: The maximum allowed lifetime of tokens issued in
            seconds using this role. This can be specified as an integer number of seconds
            or as a duration value like "5m".
        :type max_ttl: str | unicode
        :param period: If set, indicates that the token generated using
            this role should never expire. The token should be renewed within the duration
            specified by this value. At each renewal, the token's TTL will be set to the
            value of this parameter. This can be specified as an integer number of seconds
            or as a duration value like "5m".
        :type period: str | unicode
        :param policies: The list of policies to be set on tokens
            issued using this role.
        :type policies: array
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_role request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'type': type,
            'project_id': project_id,
            'bound_service_accounts': bound_service_accounts,
            'ttl': ttl,
            'max_ttl': max_ttl,
            'period': period,
            'policies': policies,
        }
        api_path = '/v1/auth/gcp/role/:name'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def edit_service_accounts_on_iam_role(self, name, add=None, remove=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        Edit service accounts for an existing IAM role in the method.
        This allows you to add or remove service accounts from the list of
        service accounts on the role.

        Supported methods:
            POST: /auth/gcp/role/:name/service-accounts. Produces: 204 (empty body)


        :param name: role.
        :type name: str | unicode
        :param add: The list of service accounts to add to the role's
            service accounts.
        :type add: array
        :param remove: The list of service accounts to remove from the
            role's service accounts.
        :type remove: array
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the edit_service_accounts_on_iam_role request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'add': add,
            'remove': remove,
        }
        api_path = '/v1/auth/gcp/role/:name/service-accounts'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def edit_labels_on_gce_role(self, name, add=None, remove=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        Edit labels for an existing GCE role in the backend. This allows you to add or
        remove labels (keys, values, or both) from the list of keys on the role.

        Supported methods:
            POST: /auth/gcp/role/:name/labels. Produces: 204 (empty body)


        :param name: role.
        :type name: str | unicode
        :param add: to add to the GCE role's
            bound labels.
        :type add: array
        :param remove: remove from the role's
            bound labels. If any of the specified keys do not exist, no error is returned
            (idempotent).
        :type remove: array
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the edit_labels_on_gce_role request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'add': add,
            'remove': remove,
        }
        api_path = '/v1/auth/gcp/role/:name/labels'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        Returns the previously registered role configuration.

        Supported methods:
            GET: /auth/gcp/role/:name. Produces: 200 application/json


        :param name: The name of the role to read.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_role request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
        }
        api_path = '/v1/auth/gcp/role/:name'.format(mount_point=mount_point)
        return self._adapter.get(
            url=api_path,
            json=params,
        )

    def list_roles(self, role, mount_point=DEFAULT_MOUNT_POINT):
        """
        Lists all the roles that are registered with the plugin.

        Supported methods:
            LIST: /auth/gcp/roles. Produces: 200 application/json


        :param role: The name of the role to delete.
        :type role: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the list_roles request.
        :rtype: requests.Response
        """
        params = {
            'role': role,
        }
        api_path = '/v1/auth/gcp/roles'.format(mount_point=mount_point)
        return self._adapter.list(
            url=api_path,
            json=params,
        )

    def delete_role(self, role, mount_point=DEFAULT_MOUNT_POINT):
        """
        Deletes the previously registered role.

        Supported methods:
            DELETE: /auth/gcp/role/:role. Produces: 204 (empty body)


        :param role: The name of the role to delete.
        :type role: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_role request.
        :rtype: requests.Response
        """
        params = {
            'role': role,
        }
        api_path = '/v1/auth/gcp/role/:role'.format(mount_point=mount_point)
        return self._adapter.delete(
            url=api_path,
            json=params,
        )

    def login(self, role, jwt, iam, gce, mount_point=DEFAULT_MOUNT_POINT):
        """
        Login to retrieve a Vault token. This endpoint takes a signed JSON Web Token
        (JWT) and a role name for some entity. It verifies the JWT signature with Google
        Cloud to authenticate that entity and then authorizes the entity for the given
        role.

        Supported methods:
            POST: /auth/gcp/login. Produces: 200 application/json


        :param role: The name of the role against which the login
            is being attempted.
        :type role: str | unicode
        :param jwt:
        :type jwt: str | unicode
        :param iam: a self-signed JWT.
        :type iam: signJwt
        :param gce:
        :type gce: unknown
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the login request.
        :rtype: requests.Response
        """
        params = {
            'role': role,
            'jwt': jwt,
            'iam': iam,
            'gce': gce,
        }
        api_path = '/v1/auth/gcp/login'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

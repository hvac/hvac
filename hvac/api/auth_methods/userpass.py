#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""USERPASS methods module."""
from hvac import utils
from hvac.api.vault_api_base import VaultApiBase

DEFAULT_MOUNT_POINT = 'userpass'


class Userpass(VaultApiBase):
    """USERPASS Auth Method (API).
    Reference: https://www.vaultproject.io/api/auth/userpass/index.html
    """

    def create_or_update_user(self, username, password, token_ttl=None, token_max_ttl=None, token_policies=None,
                              token_bound_cidrs=None, token_explicit_max_ttl=None, token_no_default_policy=None,
                              token_num_uses=None, token_period=None, token_type=None,
                              mount_point=DEFAULT_MOUNT_POINT):
        """
        Create/update user in userpass.

        Supported methods:
            POST: /auth/{mount_point}/users/{username}. Produces: 204 (empty body)

        :param username: The username for the user.
        :type username: str | unicode
        :param password: The password for the user. Only required when creating the user.
        :type password: str | unicode
        :param token_ttl: The incremental lifetime for generated tokens. This current value of this will be referenced
            at renewal time.
        :type token_ttl: str | unicode | int
        :param token_max_ttl: The maximum lifetime for generated tokens. This current value of this will be referenced
            at renewal time.
        :type token_max_ttl: str | unicode | int
        :param token_policies: List of policies to encode onto generated tokens. Depending on the auth method, this list
            may be supplemented by user/group/other values.
        :type token_policies: str | unicode | list
        :param token_bound_cidrs: List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate
            successfully, and ties the resulting token to these blocks as well.
        :type token_bound_cidrs: str | unicode | list
        :param token_explicit_max_ttl: If set, will encode an explicit max TTL onto the token. This is a hard cap even
            if `token_ttl` and `token_max_ttl` would otherwise allow a renewal.
        :type token_explicit_max_ttl: str | unicode | int
        :param token_no_default_policy: If set, the default policy will not be set on generated tokens; otherwise it
            will be added to the policies set in `token_policies`.
        :type token_no_default_policy: bool
        :param token_num_uses: The maximum number of times a generated token may be used (within its lifetime); 0 means
            unlimited.
        :type token_num_uses: int
        :param token_period: The period, if any, to set on the token.
        :type token_period: str | unicode | int
        :param token_type: The type of token that should be generated. Can be `service`, `batch`, or `default` to use
            the mount's tuned default (which unless changed will be `service` tokens). For token store roles, there are
            two additional possibilities: `default-service` and `default-batch` which specify the type to return unless
            the client requests a different type at generation time.
        :type token_type: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            'password': password,
        }
        params.update(
            utils.remove_nones({
                'token_ttl': token_ttl,
                'token_max_ttl': token_max_ttl,
                'token_policies': token_policies,
                'token_bound_cidrs': token_bound_cidrs,
                'token_explicit_max_ttl': token_explicit_max_ttl,
                'token_no_default_policy': token_no_default_policy,
                'token_num_uses': token_num_uses,
                'token_period': token_period,
                'token_type': token_type,
            })
        )
        api_path = '/v1/auth/{mount_point}/users/{username}'.format(mount_point=mount_point, username=username)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def list_user(self, mount_point=DEFAULT_MOUNT_POINT):
        """
        List existing users that have been created in the auth method

        Supported methods:
            LIST: /auth/{mount_point}/users. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_groups request.
        :rtype: dict
        """
        api_path = '/v1/auth/{mount_point}/users'.format(mount_point=mount_point)
        response = self._adapter.list(
            url=api_path,
        )
        return response.json()

    def read_user(self, username, mount_point=DEFAULT_MOUNT_POINT):
        """
        Read user in the auth method.

        Supported methods:
            GET: /auth/{mount_point}/users/{username}. Produces: 200 application/json

        :param username: The username for the user.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the read_group request.
        :rtype: dict
        """
        api_path = '/v1/auth/{mount_point}/users/{username}'.format(mount_point=mount_point, username=username)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    def delete_user(self, username, mount_point=DEFAULT_MOUNT_POINT):
        """
        Delete user in the auth method.

        Supported methods:
            GET: /auth/{mount_point}/users/{username}. Produces: 200 application/json

        :param username: The username for the user.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the read_group request.
        :rtype: dict
        """
        api_path = '/v1/auth/{mount_point}/users/{username}'.format(mount_point=mount_point, username=username)
        response = self._adapter.delete(
            url=api_path,
        )
        return response.json()

    def update_password_on_user(self, username, password, mount_point=DEFAULT_MOUNT_POINT):
        """
        update password for the user in userpass.

        Supported methods:
            POST: /auth/{mount_point}/users/{username}/password. Produces: 204 (empty body)

        :param username: The username for the user.
        :type username: str | unicode
        :param password: The password for the user. Only required when creating the user.
        :type password: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            'password': password,
        }
        api_path = '/v1/auth/{mount_point}/users/{username}/password'.format(mount_point=mount_point, username=username)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def login(self, username, password, mount_point=DEFAULT_MOUNT_POINT):
        """
        Log in with USERPASS credentials.

        Supported methods:
            POST: /auth/{mount_point}/login/{username}. Produces: 200 application/json

        :param username: The username for the user.
        :type username: str | unicode
        :param password: The password for the user. Only required when creating the user.
        :type password: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            'password': password,
        }
        api_path = '/v1/auth/{mount_point}/login/{username}'.format(mount_point=mount_point, username=username)
        response = self._adapter.post(
            url=api_path,
            json=params,
        )
        return response.json()

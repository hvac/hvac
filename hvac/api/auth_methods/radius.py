#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""RADIUS methods module."""
from hvac import exceptions, utils
from hvac.api.vault_api_base import VaultApiBase

DEFAULT_MOUNT_POINT = 'radius'


class Radius(VaultApiBase):
    """RADIUS Auth Method (API).

    Reference: https://www.vaultproject.io/docs/auth/radius.html
    """

    def configure(self, host, secret, port=None, unregistered_user_policies=None, dial_timeout=None, nas_port=None,
                  token_ttl=None, token_max_ttl=None, token_policies=None, token_bound_cidrs=None,
                  token_explicit_max_ttl=None, token_no_default_policy=None, token_num_uses=None, token_period=None,
                  token_type=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        Configure the RADIUS auth method.

        Supported methods:
            POST: /auth/{mount_point}/config. Produces: 204 (empty body)

        :param host: The RADIUS server to connect to. Examples: radius.myorg.com, 127.0.0.1
        :type host: str | unicode
        :param secret: The RADIUS shared secret.
        :type secret: str | unicode
        :param port: The UDP port where the RADIUS server is listening on. Defaults is 1812.
        :type port: int
        :param unregistered_user_policies: A comma-separated list of policies to be granted to unregistered users.
        :type unregistered_user_policies: str | unicode
        :param dial_timeout: Number of second to wait for a backend connection before timing out. Default is 10.
        :type dial_timeout: int
        :param nas_port: The NAS-Port attribute of the RADIUS request. Defaults is 10.
        :type nas_port: int
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
        :return: The response of the configure request.
        :rtype: requests.Response
        """
        params = {
            'host': host,
            'secret': secret,
        }
        params.update(
            utils.remove_nones({
                'port': port,
                'dial_timeout': dial_timeout,
                'nas_port': nas_port,
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
        # Fill out params dictionary with any optional parameters provided
        if unregistered_user_policies is not None:
            if not isinstance(unregistered_user_policies, list):
                error_msg = (
                    '"unregistered_user_policies" argument must be an instance of list or None, '
                    '"{unregistered_user_policies}" provided.'
                ).format(unregistered_user_policies=type(unregistered_user_policies))
                raise exceptions.ParamValidationError(error_msg)

            params['unregistered_user_policies'] = ','.join(unregistered_user_policies)

        api_path = utils.format_url('/v1/auth/{mount_point}/config', mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_configuration(self, mount_point=DEFAULT_MOUNT_POINT):
        """
        Retrieve the RADIUS configuration for the auth method.

        Supported methods:
            GET: /auth/{mount_point}/config. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the read_configuration request.
        :rtype: dict
        """
        api_path = utils.format_url('/v1/auth/{mount_point}/config', mount_point=mount_point)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    def register_user(self, username, policies=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        Create or update RADIUS user with a set of policies.

        Supported methods:
            POST: /auth/{mount_point}/users/{username}. Produces: 204 (empty body)

        :param username: Username for this RADIUS user.
        :type username: str | unicode
        :param policies: List of policies associated with the user. This parameter is transformed to a comma-delimited
            string before being passed to Vault.
        :type policies: list
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the register_user request.
        :rtype: requests.Response
        """
        if policies is not None and not isinstance(policies, list):
            error_msg = '"policies" argument must be an instance of list or None, "{policies_type}" provided.'.format(
                policies_type=type(policies),
            )
            raise exceptions.ParamValidationError(error_msg)

        params = {}
        if policies is not None:
            params['policies'] = ','.join(policies)
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/users/{name}',
            mount_point=mount_point,
            name=username,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def list_users(self, mount_point=DEFAULT_MOUNT_POINT):
        """
        List existing users in the method.

        Supported methods:
            LIST: /auth/{mount_point}/users. Produces: 200 application/json


        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_users request.
        :rtype: dict
        """
        api_path = utils.format_url('/v1/auth/{mount_point}/users', mount_point=mount_point)
        response = self._adapter.list(
            url=api_path,
        )
        return response.json()

    def read_user(self, username, mount_point=DEFAULT_MOUNT_POINT):
        """
        Read policies associated with a RADIUS user.

        Supported methods:
            GET: /auth/{mount_point}/users/{username}. Produces: 200 application/json


        :param username: The username of the RADIUS user
        :type username: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the read_user request.
        :rtype: dict
        """
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/users/{username}',
            mount_point=mount_point,
            username=username,
        )
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    def delete_user(self, username, mount_point=DEFAULT_MOUNT_POINT):
        """
        Delete a RADIUS user and policy association.

        Supported methods:
            DELETE: /auth/{mount_point}/users/{username}. Produces: 204 (empty body)


        :param username: The username of the RADIUS user
        :type username: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_user request.
        :rtype: requests.Response
        """
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/users/{username}',
            mount_point=mount_point,
            username=username,
        )
        return self._adapter.delete(
            url=api_path,
        )

    def login(self, username, password, use_token=True, mount_point=DEFAULT_MOUNT_POINT):
        """
        Log in with RADIUS credentials.

        Supported methods:
            POST: /auth/{mount_point}/login/{username}. Produces: 200 application/json


        :param username: The username of the RADIUS user
        :type username: str | unicode
        :param password: The password for the RADIUS user
        :type password: str | unicode
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the the :py:meth:`hvac.adapters.Adapter` instance under the _adapater Client attribute.
        :type use_token: bool
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the login_with_user request.
        :rtype: requests.Response
        """
        params = {
            'password': password,
        }
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/login/{username}',
            mount_point=mount_point,
            username=username,
        )
        return self._adapter.login(
            url=api_path,
            use_token=use_token,
            json=params,
        )

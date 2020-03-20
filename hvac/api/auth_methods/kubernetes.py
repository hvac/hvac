#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Kubernetes methods module."""
from hvac import exceptions, utils
from hvac.api.vault_api_base import VaultApiBase
from hvac.utils import validate_list_of_strings_param, comma_delimited_to_list, validate_pem_format

DEFAULT_MOUNT_POINT = 'kubernetes'


class Kubernetes(VaultApiBase):
    """Kubernetes Auth Method (API).

    Reference: https://www.vaultproject.io/api/auth/kubernetes/index.html
    """
    def configure(self, kubernetes_host, kubernetes_ca_cert=None, token_reviewer_jwt=None, pem_keys=None,
                  mount_point=DEFAULT_MOUNT_POINT):
        """Configure the connection parameters for Kubernetes.

        This path honors the distinction between the create and update capabilities inside ACL policies.

        Supported methods:
            POST: /auth/{mount_point}/config. Produces: 204 (empty body)

        :param kubernetes_host: Host must be a host string, a host:port pair, or a URL to the base of the
            Kubernetes API server. Example: https://k8s.example.com:443
        :type kubernetes_host: str | unicode
        :param kubernetes_ca_cert: PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API.
            NOTE: Every line must end with a newline: \n
        :type kubernetes_ca_cert: str | unicode
        :param token_reviewer_jwt: A service account JWT used to access the TokenReview API to validate other
            JWTs during login. If not set the JWT used for login will be used to access the API.
        :type token_reviewer_jwt: str | unicode
        :param pem_keys: Optional list of PEM-formatted public keys or certificates used to verify the signatures of
            Kubernetes service account JWTs. If a certificate is given, its public key will be extracted. Not every
            installation of Kubernetes exposes these keys.
        :type pem_keys: list
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the configure_method request.
        :rtype: requests.Response
        """
        list_of_pem_params = {
            'kubernetes_ca_cert': kubernetes_ca_cert,
            'pem_keys': pem_keys
        }
        for param_name, param_argument in list_of_pem_params.items():
            if param_argument is not None:
                validate_pem_format(
                    param_name=param_name,
                    param_argument=param_argument,
                )

        params = {
            'kubernetes_host': kubernetes_host,
        }
        params.update(
            utils.remove_nones({
                'kubernetes_ca_cert': kubernetes_ca_cert,
                'token_reviewer_jwt': token_reviewer_jwt,
                'pem_keys': pem_keys,
            })
        )
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/config',
            mount_point=mount_point
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_config(self, mount_point=DEFAULT_MOUNT_POINT):
        """Return the previously configured config, including credentials.

        Supported methods:
            GET: /auth/{mount_point}/config. Produces: 200 application/json

        :param mount_point: The "path" the kubernetes auth method was mounted on.
        :type mount_point: str | unicode
        :return: The data key from the JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url('/v1/auth/{mount_point}/config', mount_point=mount_point)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json().get('data')

    def create_role(self, name, bound_service_account_names, bound_service_account_namespaces, audience=None,
                    token_ttl=None, token_max_ttl=None, token_policies=None, token_bound_cidrs=None,
                    token_explicit_max_ttl=None, token_no_default_policy=None, token_num_uses=None,
                    token_period=None, token_type=None, mount_point=DEFAULT_MOUNT_POINT):
        """Create a role in the method.

        Registers a role in the auth method. Role types have specific entities that can perform login operations
        against this endpoint. Constraints specific to the role type must be set on the role. These are applied to
        the authenticated entities attempting to login.

        Supported methods:
            POST: /auth/{mount_point}/role/{name}. Produces: 204 (empty body)

        :param name: Name of the role.
        :type name: str | unicode
        :param bound_service_account_names: List of service account names able to access this role. If set to "*"
            all names are allowed, both this and bound_service_account_namespaces can not be "*".
        :type bound_service_account_names: list | str | unicode
        :param bound_service_account_namespaces: List of namespaces allowed to access this role. If set to "*" all
            namespaces are allowed, both this and bound_service_account_names can not be set to "*".
        :type bound_service_account_namespaces: list | str | unicode
        :param audience: Optional Audience claim to verify in the JWT.
        :type audience: str | unicode
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
        :param mount_point: The "path" the azure auth method was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        list_of_strings_params = {
            'bound_service_account_names': bound_service_account_names,
            'bound_service_account_namespaces': bound_service_account_namespaces,
        }
        for param_name, param_argument in list_of_strings_params.items():
            validate_list_of_strings_param(
                param_name=param_name,
                param_argument=param_argument,
            )

        if bound_service_account_names in ("*", ["*"]) and bound_service_account_namespaces in ("*", ["*"]):
            error_msg = 'unsupported combination of `bind_service_account_names` and ' \
                        '`bound_service_account_namespaces` arguments. Both of them can not be set to `*`'
            raise exceptions.ParamValidationError(error_msg)

        params = {
            'bound_service_account_names': comma_delimited_to_list(bound_service_account_names),
            'bound_service_account_namespaces': comma_delimited_to_list(bound_service_account_namespaces),
        }
        params.update(
            utils.remove_nones({
                'audience': audience,
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

        api_path = utils.format_url('/v1/auth/{mount_point}/role/{name}', mount_point=mount_point, name=name)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Returns the previously registered role configuration.

        Supported methods:
            POST: /auth/{mount_point}/role/{name}. Produces: 200 application/json

        :param name: Name of the role.
        :type name: str | unicode
        :param mount_point: The "path" the kubernetes auth method was mounted on.
        :type mount_point: str | unicode
        :return: The "data" key from the JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/role/{name}',
            mount_point=mount_point,
            name=name,
        )
        response = self._adapter.get(
            url=api_path,
        )
        return response.json().get('data')

    def list_roles(self, mount_point=DEFAULT_MOUNT_POINT):
        """List all the roles that are registered with the plugin.

        Supported methods:
            LIST: /auth/{mount_point}/role. Produces: 200 application/json

        :param mount_point: The "path" the kubernetes auth method was mounted on.
        :type mount_point: str | unicode
        :return: The "data" key from the JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url('/v1/auth/{mount_point}/role', mount_point=mount_point)
        response = self._adapter.list(
            url=api_path,
        )
        return response.json().get('data')

    def delete_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Delete the previously registered role.

        Supported methods:
            DELETE: /auth/{mount_point}/role/{name}. Produces: 204 (empty body)


        :param name: Name of the role.
        :type name: str | unicode
        :param mount_point: The "path" the kubernetes auth method was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/role/{name}',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.delete(
            url=api_path,
        )

    def login(self, role, jwt, use_token=True, mount_point=DEFAULT_MOUNT_POINT):
        """Fetch a token.

        This endpoint takes a signed JSON Web Token (JWT) and a role name for some entity. It verifies the JWT signature
        to authenticate that entity and then authorizes the entity for the given role.

        Supported methods:
            POST: /auth/{mount_point}/login. Produces: 200 application/json

        :param role: Name of the role against which the login is being attempted.
        :type role: str | unicode
        :param jwt: Signed JSON Web Token (JWT) from Azure MSI.
        :type jwt: str | unicode
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the the :py:meth:`hvac.adapters.Adapter` instance under the _adapater Client attribute.
        :type use_token: bool
        :param mount_point: The "path" the azure auth method was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        params = {
            'role': role,
            'jwt': jwt,
        }

        api_path = utils.format_url('/v1/auth/{mount_point}/login', mount_point=mount_point)
        response = self._adapter.login(
            url=api_path,
            use_token=use_token,
            json=params,
        )
        return response

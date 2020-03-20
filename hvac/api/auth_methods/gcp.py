#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""GCP methods module."""
import logging

from hvac import exceptions, utils
from hvac.api.vault_api_base import VaultApiBase
from hvac.constants.gcp import ALLOWED_ROLE_TYPES, GCP_CERTS_ENDPOINT
from hvac.utils import validate_list_of_strings_param, list_to_comma_delimited

DEFAULT_MOUNT_POINT = 'gcp'

logger = logging.getLogger(__name__)


class Gcp(VaultApiBase):
    """Google Cloud Auth Method (API).

    Reference: https://www.vaultproject.io/api/auth/{mount_point}/index.html
    """

    def configure(self, credentials=None, google_certs_endpoint=GCP_CERTS_ENDPOINT, mount_point=DEFAULT_MOUNT_POINT):
        """Configure the credentials required for the GCP auth method to perform API calls to Google Cloud.

        These credentials will be used to query the status of IAM entities and get service account or other Google
        public certificates to confirm signed JWTs passed in during login.

        Supported methods:
            POST: /auth/{mount_point}/config. Produces: 204 (empty body)


        :param credentials: A JSON string containing the contents of a GCP credentials file. The credentials file must
            have the following permissions: `iam.serviceAccounts.get`, `iam.serviceAccountKeys.get`.
            If this value is empty, Vault will try to use Application Default Credentials from the machine on which the
            Vault server is running. The project must have the iam.googleapis.com API enabled.
        :type credentials: str | unicode
        :param google_certs_endpoint: The Google OAuth2 endpoint from which to obtain public certificates. This is used
            for testing and should generally not be set by end users.
        :type google_certs_endpoint: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        params = utils.remove_nones({
            'credentials': credentials,
            'google_certs_endpoint': google_certs_endpoint,
        })
        api_path = utils.format_url('/v1/auth/{mount_point}/config', mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_config(self, mount_point=DEFAULT_MOUNT_POINT):
        """Read the configuration, if any, including credentials.

        Supported methods:
            GET: /auth/{mount_point}/config. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The data key from the JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url('/v1/auth/{mount_point}/config', mount_point=mount_point)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json().get('data')

    def delete_config(self, mount_point=DEFAULT_MOUNT_POINT):
        """Delete all GCP configuration data. This operation is idempotent.

        Supported methods:
            DELETE: /auth/{mount_point}/config. Produces: 204 (empty body)


        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url('/v1/auth/{mount_point}/config', mount_point=mount_point)
        return self._adapter.delete(
            url=api_path,
        )

    def create_role(self, name, role_type, project_id, bound_service_accounts=None, max_jwt_exp=None,
                    allow_gce_inference=None, bound_zones=None, bound_regions=None, bound_instance_groups=None,
                    bound_labels=None, token_ttl=None, token_max_ttl=None, token_policies=None,
                    token_bound_cidrs=None, token_explicit_max_ttl=None, token_no_default_policy=None,
                    token_num_uses=None, token_period=None, token_type=None, mount_point=DEFAULT_MOUNT_POINT):
        """Register a role in the GCP auth method.

        Role types have specific entities that can perform login operations against this endpoint. Constraints specific
            to the role type must be set on the role. These are applied to the authenticated entities attempting to
            login.

        Supported methods:
            POST: /auth/{mount_point}/role/{name}. Produces: 204 (empty body)


        :param name: The name of the role.
        :type name: str | unicode
        :param role_type: The type of this role. Certain fields correspond to specific roles and will be rejected
            otherwise.
        :type role_type: str | unicode
        :param project_id: The GCP project ID. Only entities belonging to this project can authenticate with this role.
        :type project_id: str | unicode
        :param bound_service_accounts: <required for iam> A list of service account emails or IDs that login is
            restricted  to. If set to `*`, all service accounts are allowed (role will still be bound by project). Will be
            inferred from service account used to issue metadata token for GCE instances.
        :type bound_service_accounts: list
        :param max_jwt_exp: <iam only> The number of seconds past the time of authentication that the login param JWT
            must expire within. For example, if a user attempts to login with a token that expires within an hour and
            this is set to 15 minutes, Vault will return an error prompting the user to create a new signed JWT with a
            shorter exp. The GCE metadata tokens currently do not allow the exp claim to be customized.
        :type max_jwt_exp: str | unicode
        :param allow_gce_inference: <iam only> A flag to determine if this role should allow GCE instances to
            authenticate by inferring service accounts from the GCE identity metadata token.
        :type allow_gce_inference: bool
        :param bound_zones: <gce only> The list of zones that a GCE instance must belong to in order to be
            authenticated. If bound_instance_groups is provided, it is assumed to be a zonal group and the group must
            belong to this zone.
        :type bound_zones: list
        :param bound_regions: <gce only> The list of regions that a GCE instance must belong to in order to be
            authenticated. If bound_instance_groups is provided, it is assumed to be a regional group and the group
            must belong to this region. If bound_zones are provided, this attribute is ignored.
        :type bound_regions: list
        :param bound_instance_groups: <gce only> The instance groups that an authorized instance must belong to in
            order to be authenticated. If specified, either bound_zones or bound_regions must be set too.
        :type bound_instance_groups: list
        :param bound_labels: <gce only> A list of GCP labels formatted as "key:value" strings that must be set on
            authorized GCE instances. Because GCP labels are not currently ACL'd, we recommend that this be used in
            conjunction with other restrictions.
        :type bound_labels: list
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
        :return: The data key from the JSON response of the request.
        :rtype: requests.Response
        """
        type_specific_params = {
            'iam': {
                'max_jwt_exp': None,
                'allow_gce_inference': None,
            },
            'gce': {
                'bound_zones': None,
                'bound_regions': None,
                'bound_instance_groups': None,
                'bound_labels': None,
            },
        }

        list_of_strings_params = {
            'bound_service_accounts': bound_service_accounts,
            'bound_zones': bound_zones,
            'bound_regions': bound_regions,
            'bound_instance_groups': bound_instance_groups,
            'bound_labels': bound_labels,

        }
        for param_name, param_argument in list_of_strings_params.items():
            validate_list_of_strings_param(
                param_name=param_name,
                param_argument=param_argument,
            )

        if role_type not in ALLOWED_ROLE_TYPES:
            error_msg = 'unsupported role_type argument provided "{arg}", supported types: "{role_types}"'
            raise exceptions.ParamValidationError(error_msg.format(
                arg=type,
                role_types=','.join(ALLOWED_ROLE_TYPES),
            ))

        params = {
            'type': role_type,
            'project_id': project_id,
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
        if bound_service_accounts is not None:
            params['bound_service_accounts'] = list_to_comma_delimited(bound_service_accounts)
        if role_type == 'iam':
            params.update(
                utils.remove_nones({
                    'max_jwt_exp': max_jwt_exp,
                    'allow_gce_inference': allow_gce_inference,
                })
            )
            for param, default_arg in type_specific_params['gce'].items():
                if locals().get(param) != default_arg:
                    warning_msg = 'Argument for parameter "{param}" ignored for role type iam'.format(
                        param=param
                    )
                    logger.warning(warning_msg)
        elif role_type == 'gce':
            if bound_zones is not None:
                params['bound_zones'] = list_to_comma_delimited(bound_zones)
            if bound_regions is not None:
                params['bound_regions'] = list_to_comma_delimited(bound_regions)
            if bound_instance_groups is not None:
                params['bound_instance_groups'] = list_to_comma_delimited(bound_instance_groups)
            if bound_labels is not None:
                params['bound_labels'] = list_to_comma_delimited(bound_labels)
            for param, default_arg in type_specific_params['iam'].items():
                if locals().get(param) != default_arg:
                    warning_msg = 'Argument for parameter "{param}" ignored for role type gce'.format(
                        param=param
                    )
                    logger.warning(warning_msg)

        api_path = utils.format_url(
            '/v1/auth/{mount_point}/role/{name}',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def edit_service_accounts_on_iam_role(self, name, add=None, remove=None, mount_point=DEFAULT_MOUNT_POINT):
        """Edit service accounts for an existing IAM role in the GCP auth method.

        This allows you to add or remove service accounts from the list of service accounts on the role.

        Supported methods:
            POST: /auth/{mount_point}/role/{name}/service-accounts. Produces: 204 (empty body)


        :param name: The name of an existing iam type role. This will return an error if role is not an iam type role.
        :type name: str | unicode
        :param add: The list of service accounts to add to the role's service accounts.
        :type add: list
        :param remove: The list of service accounts to remove from the role's service accounts.
        :type remove: list
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        params = utils.remove_nones({
            'add': add,
            'remove': remove,
        })
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/role/{name}/service-accounts',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def edit_labels_on_gce_role(self, name, add=None, remove=None, mount_point=DEFAULT_MOUNT_POINT):
        """Edit labels for an existing GCE role in the backend.

        This allows you to add or remove labels (keys, values, or both) from the list of keys on the role.

        Supported methods:
            POST: /auth/{mount_point}/role/{name}/labels. Produces: 204 (empty body)


        :param name: The name of an existing gce role. This will return an error if role is not a gce type role.
        :type name: str | unicode
        :param add: The list of key:value labels to add to the GCE role's bound labels.
        :type add: list
        :param remove: The list of label keys to remove from the role's bound labels. If any of the specified keys do
            not exist, no error is returned (idempotent).
        :type remove: list
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the edit_labels_on_gce_role request.
        :rtype: requests.Response
        """
        params = utils.remove_nones({
            'add': add,
            'remove': remove,
        })
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/role/{name}/labels',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Read the previously registered role configuration.

        Supported methods:
            GET: /auth/{mount_point}/role/{name}. Produces: 200 application/json


        :param name: The name of the role to read.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The data key from the JSON response of the read_role request.
        :rtype: JSON
        """
        params = {
            'name': name,
        }
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/role/{name}',
            mount_point=mount_point,
            name=name,
        )
        response = self._adapter.get(
            url=api_path,
            json=params,
        )
        return response.json().get('data')

    def list_roles(self, mount_point=DEFAULT_MOUNT_POINT):
        """List all the roles that are registered with the plugin.

        Supported methods:
            LIST: /auth/{mount_point}/roles. Produces: 200 application/json


        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The data key from the JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url('/v1/auth/{mount_point}/roles', mount_point=mount_point)
        response = self._adapter.list(
            url=api_path,
        )
        return response.json().get('data')

    def delete_role(self, role, mount_point=DEFAULT_MOUNT_POINT):
        """Delete the previously registered role.

        Supported methods:
            DELETE: /auth/{mount_point}/role/{role}. Produces: 204 (empty body)


        :param role: The name of the role to delete.
        :type role: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        params = {
            'role': role,
        }
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/role/{role}',
            mount_point=mount_point,
            role=role,
        )
        return self._adapter.delete(
            url=api_path,
            json=params,
        )

    def login(self, role, jwt, use_token=True, mount_point=DEFAULT_MOUNT_POINT):
        """Login to retrieve a Vault token via the GCP auth method.

        This endpoint takes a signed JSON Web Token (JWT) and a role name for some entity. It verifies the JWT
            signature with Google Cloud to authenticate that entity and then authorizes the entity for the given role.

        Supported methods:
            POST: /auth/{mount_point}/login. Produces: 200 application/json


        :param role: The name of the role against which the login is being attempted.
        :type role: str | unicode
        :param jwt: A signed JSON web token
        :type jwt: str | unicode
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the the :py:meth:`hvac.adapters.Adapter` instance under the _adapater Client attribute.
        :type use_token: bool
        :param mount_point: The "path" the method/backend was mounted on.
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

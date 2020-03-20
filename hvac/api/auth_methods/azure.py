#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Azure auth method module."""
import logging

from hvac import exceptions, utils
from hvac.api.vault_api_base import VaultApiBase
from hvac.constants.azure import VALID_ENVIRONMENTS

DEFAULT_MOUNT_POINT = 'azure'
logger = logging.getLogger(__name__)


class Azure(VaultApiBase):
    """Azure Auth Method (API).

    Reference: https://www.vaultproject.io/api/auth/azure/index.html
    """

    def configure(self, tenant_id, resource, environment=None, client_id=None, client_secret=None,
                  mount_point=DEFAULT_MOUNT_POINT):
        """Configure the credentials required for the plugin to perform API calls to Azure.

        These credentials will be used to query the metadata about the virtual machine.

        Supported methods:
            POST: /auth/{mount_point}/config. Produces: 204 (empty body)

        :param tenant_id: The tenant id for the Azure Active Directory organization.
        :type tenant_id: str | unicode
        :param resource: The configured URL for the application registered in Azure Active Directory.
        :type resource: str | unicode
        :param environment: The Azure cloud environment. Valid values: AzurePublicCloud, AzureUSGovernmentCloud,
            AzureChinaCloud, AzureGermanCloud.
        :type environment: str | unicode
        :param client_id: The client id for credentials to query the Azure APIs.  Currently read permissions to query
            compute resources are required.
        :type client_id: str | unicode
        :param client_secret: The client secret for credentials to query the Azure APIs.
        :type client_secret: str | unicode
        :param mount_point: The "path" the azure auth method was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        if environment is not None and environment not in VALID_ENVIRONMENTS:
            error_msg = 'invalid environment argument provided: "{arg}"; supported environments: "{environments}"'
            raise exceptions.ParamValidationError(error_msg.format(
                arg=environment,
                environments=','.join(VALID_ENVIRONMENTS),
            ))
        params = {
            'tenant_id': tenant_id,
            'resource': resource,
        }
        params.update(
            utils.remove_nones({
                'environment': environment,
                'client_id': client_id,
                'client_secret': client_secret,
            })
        )
        api_path = utils.format_url('/v1/auth/{mount_point}/config', mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_config(self, mount_point=DEFAULT_MOUNT_POINT):
        """Return the previously configured config, including credentials.

        Supported methods:
            GET: /auth/{mount_point}/config. Produces: 200 application/json

        :param mount_point: The "path" the azure auth method was mounted on.
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
        """Delete the previously configured Azure config and credentials.

        Supported methods:
            DELETE: /auth/{mount_point}/config. Produces: 204 (empty body)

        :param mount_point: The "path" the azure auth method was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url('/v1/auth/{mount_point}/config', mount_point=mount_point)
        return self._adapter.delete(
            url=api_path,
        )

    def create_role(self, name, bound_service_principal_ids=None, bound_group_ids=None, bound_locations=None,
                    bound_subscription_ids=None, bound_resource_groups=None, bound_scale_sets=None,
                    token_ttl=None, token_max_ttl=None, token_policies=None, token_bound_cidrs=None,
                    token_explicit_max_ttl=None, token_no_default_policy=None, token_num_uses=None,
                    token_period=None, token_type=None, mount_point=DEFAULT_MOUNT_POINT):
        """Create a role in the method.

        Role types have specific entities that can perform login operations against this endpoint. Constraints specific
        to the role type must be set on the role. These are applied to the authenticated entities attempting to login.

        Supported methods:
            POST: /auth/{mount_point}/role/{name}. Produces: 204 (empty body)


        :param name: Name of the role.
        :type name: str | unicode
        :param bound_service_principal_ids: The list of Service Principal IDs that login is restricted to.
        :type bound_service_principal_ids: list
        :param bound_group_ids: The list of group ids that login is restricted to.
        :type bound_group_ids: list
        :param bound_locations: The list of locations that login is restricted to.
        :type bound_locations: list
        :param bound_subscription_ids: The list of subscription IDs that login is restricted to.
        :type bound_subscription_ids: list
        :param bound_resource_groups: The list of resource groups that login is restricted to.
        :type bound_resource_groups: list
        :param bound_scale_sets: The list of scale set names that the login is restricted to.
        :type bound_scale_sets: list
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
        :param mount_point: The "path" the azure auth method was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        if token_policies is not None:
            if not (
                isinstance(token_policies, str)
                or (isinstance(token_policies, list) and all([isinstance(p, str) for p in token_policies]))
            ):
                error_msg = 'unsupported token_policies argument provided "{arg}" ({arg_type}), required type: str or List[str]"'
                raise exceptions.ParamValidationError(error_msg.format(
                    arg=token_policies,
                    arg_type=type(token_policies),
                ))
        params = utils.remove_nones({
            'bound_service_principal_ids': bound_service_principal_ids,
            'bound_group_ids': bound_group_ids,
            'bound_locations': bound_locations,
            'bound_subscription_ids': bound_subscription_ids,
            'bound_resource_groups': bound_resource_groups,
            'bound_scale_sets': bound_scale_sets,
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

        api_path = utils.format_url('/v1/auth/{mount_point}/role/{name}', mount_point=mount_point, name=name)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Read the previously registered role configuration.

        Supported methods:
            GET: /auth/{mount_point}/role/{name}. Produces: 200 application/json


        :param name: Name of the role.
        :type name: str | unicode
        :param mount_point: The "path" the azure auth method was mounted on.
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


        :param mount_point: The "path" the azure auth method was mounted on.
        :type mount_point: str | unicode
        :return: The "data" key from the JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url('/v1/auth/{mount_point}/role', mount_point=mount_point)
        response = self._adapter.list(
            url=api_path
        )
        return response.json().get('data')

    def delete_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Delete the previously registered role.

        Supported methods:
            DELETE: /auth/{mount_point}/role/{name}. Produces: 204 (empty body)


        :param name: Name of the role.
        :type name: str | unicode
        :param mount_point: The "path" the azure auth method was mounted on.
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

    def login(self, role, jwt, subscription_id=None, resource_group_name=None, vm_name=None, vmss_name=None, use_token=True,
              mount_point=DEFAULT_MOUNT_POINT):
        """Fetch a token.

        This endpoint takes a signed JSON Web Token (JWT) and a role name for some entity. It verifies the JWT signature
        to authenticate that entity and then authorizes the entity for the given role.

        Supported methods:
            POST: /auth/{mount_point}/login. Produces: 200 application/json


        :param role: Name of the role against which the login is being attempted.
        :type role: str | unicode
        :param jwt: Signed JSON Web Token (JWT) from Azure MSI.
        :type jwt: str | unicode
        :param subscription_id: The subscription ID for the machine that generated the MSI token. This information can
            be obtained through instance metadata.
        :type subscription_id: str | unicode
        :param resource_group_name: The resource group for the machine that generated the MSI token. This information
            can be obtained through instance metadata.
        :type resource_group_name: str | unicode
        :param vm_name: The virtual machine name for the machine that generated the MSI token. This information can be
            obtained through instance metadata.  If vmss_name is provided, this value is ignored.
        :type vm_name: str | unicode
        :param vmss_name: The virtual machine scale set name for the machine that generated the MSI token. This
            information can be obtained through instance metadata.
        :type vmss_name: str | unicode
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
        params.update(
            utils.remove_nones({
                'subscription_id': subscription_id,
                'resource_group_name': resource_group_name,
                'vm_name': vm_name,
                'vmss_name': vmss_name,
            })
        )
        api_path = utils.format_url('/v1/auth/{mount_point}/login', mount_point=mount_point)
        response = self._adapter.login(
            url=api_path,
            use_token=use_token,
            json=params,
        )
        return response

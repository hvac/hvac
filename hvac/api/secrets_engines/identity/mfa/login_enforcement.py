"""Collection of classes for various Vault identity MFA methods."""
from hvac import exceptions, utils
from hvac.api.vault_api_base import VaultApiBase
from hvac.constants.identity import DEFAULT_MOUNT_POINT

__all__ = ("LoginEnforcement",)


class LoginEnforcement(VaultApiBase):
    """Identity MFA Login Enforcement Methods (API).
    Reference: https://developer.hashicorp.com/vault/api-docs/secret/identity/mfa/login-enforcement
    """

    def create_or_update_login_enforcement(
        self,
        name,
        mfa_method_ids,
        auth_method_accessors=None,
        auth_method_types=None,
        identity_group_ids=None,
        identity_entity_ids=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        Create/update an MFA login enforcement.

        Supported methods:
            POST: /{mount_point}/mfa/login-enforcement/{name}. Produces: 204 (empty body)

        :param name: The name of the login enforcement configuration.
        :type name: str | unicode
        :param mfa_method_ids: List of MFA method UUIDs. If several IDs are specified,
            any of them is sufficient to login.
        :type mfa_method_ids: list[str]
        :param auth_method_accessors: List of auth mount accessor IDs. If present,
            only these accessors have login MFA enforced.
        :type auth_method_accessors: list[str]
        :param auth_method_types: List of auth method types. If present, only auth
            methods of these types have login MFA enforced.
        :type auth_method_types: list[str]
        :param identity_group_ids: List of identity group IDs. If present, only members
            of these identity groups have login MFA enforced. These IDs can be from the
            current namespace or a child namespace.
        :type identity_group_ids: list[str]
        :param identity_entity_ids: List of identity entity IDs. If present, only these
            identity entities have login MFA enforced. These IDs can be from the
            current namespace or a child namespace.
        :type identity_entity_ids: list[str]
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        if not (
            auth_method_accessors
            or auth_method_types
            or identity_group_ids
            or identity_entity_ids
        ):
            raise exceptions.ParamValidationError(
                "You must include at least one of auth_method_accessors or auth_method_types"
                " or identity_group_ids or identity_entity_ids."
            )

        list_of_strings_params = {
            "mfa_method_ids": mfa_method_ids,
            "auth_method_accessors": auth_method_accessors,
            "auth_method_types": auth_method_types,
            "identity_group_ids": identity_group_ids,
            "identity_entity_ids": identity_entity_ids,
        }

        for param_name, param_argument in list_of_strings_params.items():
            utils.validate_list_of_strings_param(
                param_name=param_name,
                param_argument=param_argument,
            )

        params = utils.remove_nones(list_of_strings_params)

        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/login-enforcement/{name}",
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(url=api_path, json=params)

    def list_login_enforcements(self, mount_point=DEFAULT_MOUNT_POINT):
        """
        List existing login enforcements in current or parent namespaces.

        Supported methods:
            LIST: /auth/{mount_point}/role. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_login_enforcements request.
        :rtype: dict
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/login-enforcement",
            mount_point=mount_point,
        )
        return self._adapter.list(url=api_path)

    def read_login_enforcement(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        Read named login enforcement configuration.

        Supported methods:
            GET: /auth/{mount_point}/mfa/login-enforcement/{name}. Produces: 200 application/json

        :param name: The name for the login enforcement.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the read_login_enforcement request.
        :rtype: dict
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/login-enforcement/{name}",
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.get(url=api_path)

    def delete_login_enforcement(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        Delete named login enforcement configuration.

        Supported methods:
            DELETE: /auth/{mount_point}/mfa/login-enforcement/{name}. Produces: 204 (empty body)

        :param name: The name for the login enforcement.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/login-enforcement/{name}",
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.delete(url=api_path)

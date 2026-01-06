from hvac import utils
from hvac.api.secrets_engines.identity.mfa.mfa_method_mixin import MfaMethodMixin
from hvac.constants.identity import DEFAULT_MOUNT_POINT


class Duo(MfaMethodMixin):
    """Identity MFA Duo MFA Method (API).

    Reference: https://developer.hashicorp.com/vault/api-docs/secret/identity/mfa/duo
    """

    method_type = "duo"

    def create(
        self,
        secret_key,
        integration_key,
        api_hostname,
        push_info=None,
        method_name=None,
        username_format=None,
        use_passcode=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        Create an MFA Method of method_type Duo.

        Supported methods:
            POST: /{mount_point}/mfa/method/duo. Produces: 204 (empty body)

        :param secret_key: Secret key for Duo.
        :type secret_key: str | unicode
        :param integration_key: Integration key for Duo.
        :type integration_key: str | unicode
        :param api_hostname: API hostname for Duo.
        :type api_hostname: str | unicode
        :param push_info: Push information for Duo.
        :type push_info: str | unicode
        :param method_name: Unique name identifier for this MFA method.
            Supported from Vault 1.13.0.
        :type method_name: str | unicode
        :param username_format: Format string for mapping identity names to
            MFA method names. Values to substitute should be placed in `{{}}`.
            For example, `{{identity.entity.name}}@example.com`.
            If blank, the Entity's Name field is used as-is.
        :type username_format: str | unicode
        :param use_passcode: If set, the user is reminded to use the passcode
            upon MFA validation.
        :type use_passcode: bool
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            "secret_key": secret_key,
            "integration_key": integration_key,
            "api_hostname": api_hostname,
        }
        params.update(
            utils.remove_nones(
                {
                    "push_info": push_info,
                    "method_name": method_name,
                    "username_format": username_format,
                    "use_passcode": use_passcode,
                }
            )
        )
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/method/{method_type}",
            mount_point=mount_point,
            method_type=self.method_type,
        )
        return self._adapter.post(url=api_path, json=params)

    def update(
        self,
        method_id,
        secret_key,
        integration_key,
        api_hostname,
        push_info=None,
        method_name=None,
        username_format=None,
        use_passcode=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        Update an MFA Method of method_type Duo.

        Supported methods:
            POST: /{mount_point}/mfa/method/duo/{method_id}. Produces: 204 (empty body)

        :param method_id: The UUID of the MFA method.
        :type method_id: str | unicode
        :param secret_key: Secret key for Duo.
        :type secret_key: str | unicode
        :param integration_key: Integration key for Duo.
        :type integration_key: str | unicode
        :param api_hostname: API hostname for Duo.
        :type api_hostname: str | unicode
        :param push_info: Push information for Duo.
        :type push_info: str | unicode
        :param method_name: Unique name identifier for this MFA method.
            Supported from Vault 1.13.0.
        :type method_name: str | unicode
        :param username_format: Format string for mapping identity names to
            MFA method names. Values to substitute should be placed in `{{}}`.
            For example, `{{identity.entity.name}}@example.com`.
            If blank, the Entity's Name field is used as-is.
        :param use_passcode: If set, the user is reminded to use the passcode
            upon MFA validation.
        :type use_passcode: bool
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            "secret_key": secret_key,
            "integration_key": integration_key,
            "api_hostname": api_hostname,
        }
        params.update(
            utils.remove_nones(
                {
                    "push_info": push_info,
                    "method_name": method_name,
                    "username_format": username_format,
                    "use_passcode": use_passcode,
                }
            )
        )
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/method/{method_type}/{method_id}",
            mount_point=mount_point,
            method_type=self.method_type,
            method_id=method_id,
        )
        return self._adapter.post(url=api_path, json=params)

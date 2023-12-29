from hvac import utils
from hvac.api.secrets_engines.identity.mfa.mfa_method_mixin import MfaMethodMixin
from hvac.constants.identity import DEFAULT_MOUNT_POINT


class PingID(MfaMethodMixin):
    method_type = "pingid"

    def create(
        self,
        settings_file_base64,
        method_name=None,
        username_format=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        Create an MFA Method of method_type PingID.

        Supported methods:
            POST: /{mount_point}/mfa/method/pingid. Produces: 204 (empty body)

        :param settings_file_base64: A base64-encoded third-party settings file
            retrieved from PingID's configuration page.
        :type settings_file_base64: str | unicode
        :param method_name: Unique name identifier for this MFA method.
            Supported from Vault 1.13.0.
        :type method_name: str | unicode
        :param username_format: Format string for mapping identity names to
            MFA method names. Values to substitute should be placed in `{{}}`.
            For example, `{{identity.entity.name}}@example.com`.
            If blank, the Entity's Name field is used as-is.
        :type username_format: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            "settings_file_base64": settings_file_base64,
        }
        params.update(
            utils.remove_nones(
                {
                    "method_name": method_name,
                    "username_format": username_format,
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
        settings_file_base64,
        method_name=None,
        username_format=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        Update an MFA Method of method_type PingID.

        Supported methods:
            POST: /{mount_point}/mfa/method/pingid/{method_id}. Produces: 204 (empty body)

        :param method_id: The UUID of the MFA method.
        :type method_id: str | unicode
        :param settings_file_base64: A base64-encoded third-party settings file
            retrieved from PingID's configuration page.
        :type settings_file_base64: str | unicode
        :param method_name: Unique name identifier for this MFA method.
            Supported from Vault 1.13.0.
        :type method_name: str | unicode
        :param username_format: Format string for mapping identity names to
            MFA method names. Values to substitute should be placed in `{{}}`.
            For example, `{{identity.entity.name}}@example.com`.
            If blank, the Entity's Name field is used as-is.
        :type username_format: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            "settings_file_base64": settings_file_base64,
        }
        params.update(
            utils.remove_nones(
                {
                    "method_name": method_name,
                    "username_format": username_format,
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

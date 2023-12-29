from hvac import utils
from hvac.api.secrets_engines.identity.mfa.mfa_method_mixin import MfaMethodMixin
from hvac.constants.identity import DEFAULT_MOUNT_POINT


class Okta(MfaMethodMixin):
    """Identity MFA Okta MFA Method (API).

    Reference: https://developer.hashicorp.com/vault/api-docs/secret/identity/mfa/okta
    """

    method_type = "okta"

    def create(
        self,
        org_name,
        api_token,
        method_name=None,
        username_format=None,
        base_url=None,
        primary_email=None,
        use_passcode=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        Create an MFA Method of method_type Okta.

        Supported methods:
            POST: /{mount_point}/mfa/method/okta. Produces: 204 (empty body)

        :param org_name: Name of the organization to use in the Okta API.
        :type org_name: str | unicode
        :param api_token: Okta API key.
        :type api_token: str | unicode
        :param method_name: Unique name identifier for this MFA method.
            Supported from Vault 1.13.0.
        :type method_name: str | unicode
        :param username_format: Format string for mapping identity names to
            MFA method names. Values to substitute should be placed in `{{}}`.
            For example, `{{identity.entity.name}}@example.com`.
            If blank, the Entity's Name field is used as-is.
        :type username_format: str | unicode
        :param base_url: If set, will be used as the base domain for API requests.
            Examples: okta.com, oktaprevew.com, okta-emea.com
        :type base_url: str | unicode
        :param primary_email: If set, the username will match the Okta profile's
            primary_email instead of the Okta profile's login.
        :type primary_email: bool
        :param use_passcode: If set, the user is reminded to use the passcode
            upon MFA validation.
        :type use_passcode: bool
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            "org_name": org_name,
            "api_token": api_token,
        }
        params.update(
            utils.remove_nones(
                {
                    "method_name": method_name,
                    "username_format": username_format,
                    "base_url": base_url,
                    "primary_email": primary_email,
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
        org_name,
        api_token,
        method_name=None,
        username_format=None,
        base_url=None,
        primary_email=None,
        use_passcode=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        Update an MFA Method of method_type Okta.

        Supported methods:
            POST: /{mount_point}/mfa/method/okta/{method_id}. Produces: 204 (empty body)

        :param method_id: The UUID of the MFA method.
        :type method_id: str | unicode
        :param org_name: Name of the organization to use in the Okta API.
        :type org_name: str | unicode
        :param api_token: Okta API key.
        :type api_token: str | unicode
        :param method_name: Unique name identifier for this MFA method.
            Supported from Vault 1.13.0.
        :type method_name: str | unicode
        :param username_format: Format string for mapping identity names to
            MFA method names. Values to substitute should be placed in `{{}}`.
            For example, `{{identity.entity.name}}@example.com`.
            If blank, the Entity's Name field is used as-is.
        :type username_format: str | unicode
        :param base_url: If set, will be used as the base domain for API requests.
            Examples: okta.com, oktaprevew.com, okta-emea.com
        :type base_url: str | unicode
        :param primary_email: If set, the username will match the Okta profile's
            primary_email instead of the Okta profile's login.
        :type primary_email: bool
        :param use_passcode: If set, the user is reminded to use the passcode
            upon MFA validation.
        :type use_passcode: bool
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            "org_name": org_name,
            "api_token": api_token,
        }
        params.update(
            utils.remove_nones(
                {
                    "method_name": method_name,
                    "username_format": username_format,
                    "base_url": base_url,
                    "primary_email": primary_email,
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

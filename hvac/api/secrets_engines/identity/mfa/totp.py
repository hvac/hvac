from hvac import utils
from hvac.api.secrets_engines.identity.mfa.mfa_method_mixin import MfaMethodMixin
from hvac.constants.identity import DEFAULT_MOUNT_POINT


class TOTP(MfaMethodMixin):
    method_type = "totp"

    def create(
        self,
        issuer,
        method_name=None,
        period=None,
        key_size=None,
        qr_size=None,
        algorithm=None,
        digits=None,
        skew=None,
        max_validation_attempts=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        Create an MFA Method of method_type TOTP.

        Supported methods:
            POST: /{mount_point}/mfa/method/totp. Produces: 204 (empty body)

        :param issuer: Name of the key's issuing organization.
        :type issuer: str | unicode
        :param method_name: Unique name identifier for this MFA method.
            Supported from Vault 1.13.0.
        :type method_name: str | unicode
        :param period: Length of time used to generate a counter for the
            TOTP token calculation as an int or a duration format string.
        :type period: int | str | unicode
        :param key_size: Size in bytes of the generated key.
        :type key_size: int
        :param qr_size: Pixel size of the generated square QR code.
        :type qr_size: int
        :param algorithm: Hashing algorithm used to generate TOTP code.
            Options include 'SHA1', 'SHA256', 'SHA512'
        :type algorithm: str | unicode
        :param digits: Number of digits in the generated TOTP token.
            Can be either 6 or 8.
        :type digits: int
        :param skew: Number of delay periods that are allowed when
            validating a TOTP token. Can be either 0 or 1.
        :type skew: int
        :param max_validation_attempts: Maximum number of consecutive
            failed validation attempts.
        :type max_validation_attempts: int
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            "issuer": issuer,
        }
        params.update(
            utils.remove_nones(
                {
                    "method_name": method_name,
                    "period": period,
                    "key_size": key_size,
                    "qr_size": qr_size,
                    "algorithm": algorithm,
                    "digits": digits,
                    "skew": skew,
                    "max_validation_attempts": max_validation_attempts,
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
        issuer,
        method_name=None,
        period=None,
        key_size=None,
        qr_size=None,
        algorithm=None,
        digits=None,
        skew=None,
        max_validation_attempts=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        Update an MFA Method of method_type TOTP.

        Supported methods:
            POST: /{mount_point}/mfa/method/totp/{method_id}. Produces: 204 (empty body)

        :param method_id: The UUID of the MFA method.
        :type method_id: str | unicode
        :param issuer: Name of the key's issuing organization.
        :type issuer: str | unicode
        :param method_name: Unique name identifier for this MFA method.
            Supported from Vault 1.13.0.
        :type method_name: str | unicode
        :param period: Length of time used to generate a counter for the
            TOTP token calculation as an int or a duration format string.
        :type period: int | str | unicode
        :param key_size: Size in bytes of the generated key.
        :type key_size: int
        :param qr_size: Pixel size of the generated square QR code.
        :type qr_size: int
        :param algorithm: Hashing algorithm used to generate TOTP code.
            Options include 'SHA1', 'SHA256', 'SHA512'
        :type algorithm: str | unicode
        :param digits: Number of digits in the generated TOTP token.
            Can be either 6 or 8.
        :type digits: int
        :param skew: Number of delay periods that are allowed when
            validating a TOTP token. Can be either 0 or 1.
        :type skew: int
        :param max_validation_attempts: Maximum number of consecutive
            failed validation attempts.
        :type max_validation_attempts: int
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        """
        params = {
            "issuer": issuer,
        }
        params.update(
            utils.remove_nones(
                {
                    "method_name": method_name,
                    "period": period,
                    "key_size": key_size,
                    "qr_size": qr_size,
                    "algorithm": algorithm,
                    "digits": digits,
                    "skew": skew,
                    "max_validation_attempts": max_validation_attempts,
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

    def generate(self, method_id, mount_point=DEFAULT_MOUNT_POINT):
        """
        Generate a TOTP MFA secret in the entity of the calling token using this MFA Method.

        Supported methods:
            POST: /{mount_point}/mfa/method/totp/generate. Produces: 200 application/json

        :param method_id: The UUID of the MFA method.
        :type method_id: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_mfa_methods request.
        :rtype: dict
        """
        params = {"method_id": method_id}
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/method/{method_type}/generate",
            mount_point=mount_point,
            method_type=self.method_type,
        )
        return self._adapter.post(url=api_path, json=params)

    def admin_generate(self, method_id, entity_id, mount_point=DEFAULT_MOUNT_POINT):
        """
        Generate a TOTP MFA secret in the given entity ID using this MFA Method.
        An admin-only operation.

        Supported methods:
            POST: /{mount_point}/mfa/method/totp/admin-generate. Produces: 200 application/json

        :param method_id: The UUID of the MFA method.
        :type method_id: str | unicode
        :param entity_id: Entity ID on which the generated secret needs to be stored.
        :type entity_id: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_mfa_methods request.
        :rtype: dict
        """
        params = {
            "method_id": method_id,
            "entity_id": entity_id,
        }
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/method/{method_type}/admin-generate",
            mount_point=mount_point,
            method_type=self.method_type,
        )
        return self._adapter.post(url=api_path, json=params)

    def admin_destroy(self, method_id, entity_id, mount_point=DEFAULT_MOUNT_POINT):
        """
        Destroy a TOTP MFA secret in the given entity ID using this MFA Method.
        An admin-only operation. Overwriting a secret on the entity requires
        explicitly deleting the secret first.

        Supported methods:
            POST: /{mount_point}/mfa/method/totp/admin-destroy. Produces: 204 (empty body)

        :param method_id: The UUID of the MFA method.
        :type method_id: str | unicode
        :param entity_id: Entity ID on which the generated secret needs to be stored.
        :type entity_id: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_mfa_methods request.
        :rtype: dict
        """
        params = {
            "method_id": method_id,
            "entity_id": entity_id,
        }
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/method/{method_type}/admin-destroy",
            mount_point=mount_point,
            method_type=self.method_type,
        )
        return self._adapter.post(url=api_path, json=params)

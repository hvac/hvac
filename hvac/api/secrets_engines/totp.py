#!/usr/bin/env python
"""TOTP vault secrets backend module."""

from hvac import exceptions,utils
from hvac.api.vault_api_base import VaultApiBase

from hvac.constants.totp import (
    DEFAULT_MOUNT_POINT,
    ALLOWED_ALGORITHMS,
    ALLOWED_DIGITS,
    ALLOWED_SKEW,
)

class Totp(VaultApiBase):
    """TOTP Secrets Engine (API).
    Reference: https://www.vaultproject.io/api-docs/secret/totp
    """

    def create_key(
        self,
        name,
        generate=False,
        exported=True,
        key_size=20,
        url="",
        key="",             # required - if generate is false and url is empty
        issuer="",          # required - if generate is true
        account_name="",    # required - if generate is true
        period=30,
        algorithm="SHA1",   # Options include "SHA1", "SHA256" and "SHA512".
        digits=6,           # This value can be set to 6 or 8.
        skew=1,             # This value can be either 0 or 1. Only used if generate is true.
        qr_size=200,        # If this value is 0, a QR code will not be returned
        mount_point=DEFAULT_MOUNT_POINT,
    ):  
        """This endpoint creates or updates a key definition.

        :param name: Specifies the name of the key to create.
        :type name: str | unicode
        :param generate: Specifies if a key should be generated by Vault or if a key is being passed from another service.
        :type generate: bool
        :param exported: Specifies if a QR code and url are returned upon generating a key. Only used if generate is true.
        :type exported: bool
        :param key_size: Specifies the size in bytes of the Vault generated key. Only used if generate is true.
        :type key_size: int
        :param url: Specifies the TOTP key url string that can be used to configure a key. Only used if generate is false.
        :type url: str | unicode
        :param key: Specifies the root key used to generate a TOTP code. Only used if generate is false.
        :type key: str | unicode
        :param issuer: Specifies the name of the key’s issuing organization.
        :type issuer: str | unicode
        :param account_name: Specifies the name of the account associated with the key.
        :type account_name: str | unicode
        :param period: Specifies the length of time in seconds used to generate a counter for the TOTP code calculation.
        :type period: int
        :param algorithm: Specifies the hashing algorithm used to generate the TOTP code. Options include "SHA1", "SHA256" and "SHA512".
        :type algorithm: str | unicode
        :param digits: Specifies the number of digits in the generated TOTP code. This value can be set to 6 or 8.
        :type digits: int
        :param skew: Specifies the number of delay periods that are allowed when validating a TOTP code. This value can be either 0 or 1. Only used if generate is true.
        :type skew: int
        :param qr_size: Specifies the pixel size of the square QR code when generating a new key. Only used if generate is true and exported is true. If this value is 0, a QR code will not be returned.
        :type qr_size: int
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: totp).
        :type mount_point: str | unicode
        :return: The response status code of the request
        :rtype: requests.Response
        """

        if generate:
            if issuer == "" or account_name == "":
                error_msg = f'required issuer and account_name when generate is true, got "{issuer}", "{account_name}"'
                raise exceptions.ParamValidationError(error_msg)
            if skew not in ALLOWED_SKEW:
                error_msg = f'value can be either 0 or 1, got "{skew}"'
                raise exceptions.ParamValidationError(error_msg)
        else:  
            if not url:
                if not key:
                    error_msg = 'key is required if generate is false and url is empty'
                    raise exceptions.ParamValidationError(error_msg)
        if algorithm not in ALLOWED_ALGORITHMS:
            error_msg = f'Options include "SHA1", "SHA256" and "SHA512", got "{algorithm}"'
            raise exceptions.ParamValidationError(error_msg)
        if digits not in ALLOWED_DIGITS:
            error_msg = f'This value can be either 0 or 1. Only used if generate is true, got "{digits}"'
            raise exceptions.ParamValidationError(error_msg)
        if not qr_size >= 0:
            error_msg = f'qr_size should greater or equal to 0, got "{qr_size}"'
            raise exceptions.ParamValidationError(error_msg)

        params = {
            "generate": generate,
            "exported": exported,
            "key_size": key_size,
            "url": url,
            "key": key,
            "issuer": issuer,
            "account_name": account_name,
            "period": period,
            "algorithm": algorithm,
            "digits": digits,
            "skew": skew,
            "qr_size": qr_size,
        }

        api_path = utils.format_url(
            "/v1/{mount_point}/keys/{name}",
            mount_point=mount_point,
            name=name
        )

        return self._adapter.post(
            url=api_path,
            json=params
        )

    def read_key(
        self,
        name,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """This endpoint queries the key definition.

        :param name: Specifies the name of the key to read. This is specified as part of the URL.
        :type name: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: totp).
        :type mount_point: str | unicode
        :return: The JSON response of the request
        :rtype: requests.Response
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/keys/{name}",
            mount_point=mount_point,
            name=name
        )

        return self._adapter.get(url=api_path)

    def list_keys(
        self,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """This endpoint returns a list of available keys. Only the key names are returned, not any values.

        :param mount_point: Specifies the place where the secrets engine will be accessible (default: totp).
        :type mount_point: str | unicode
        :return: The JSON response of the request
        :rtype: requests.Response
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/keys",
            mount_point=mount_point,
        )

        return self._adapter.list(url=api_path)

    def delete_key(
        self,
        name,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """This endpoint deletes the key definition.

        :param name: Specifies the name of the key to delete. This is specified as part of the URL.
        :type name: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: totp).
        :type mount_point: str | unicode
        :return: The response status code of the request
        :rtype: requests.Response
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/keys/{name}",
            mount_point=mount_point,
            name=name
        )

        return self._adapter.delete(url=api_path)

    def generate_code(
        self,
        name,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """This endpoint generates a new time-based one-time use password based on the named key.

        :param name: Specifies the name of the key to create credentials against. This is specified as part of the URL.
        :type name: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: totp).
        :type mount_point: str | unicode
        :return: The JSON response of the request
        :rtype: requests.Response
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/code/{name}",
            mount_point=mount_point,
            name=name
        )

        return self._adapter.get(url=api_path)

    def validate_code(
        self,
        name,
        code,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """This endpoint validates a time-based one-time use password generated from the named key.

        :param name: Specifies the name of the key used to generate the password. This is specified as part of the URL.
        :type name: str | unicode
        :param code: Specifies the password you want to validate.
        :type code: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: totp).
        :type mount_point: str | unicode
        :return: The JSON response of the request
        :rtype: requests.Response
        """
        params = {
            "code": code
        }

        api_path = utils.format_url(
            "/v1/{mount_point}/code/{name}",
            mount_point=mount_point,
            name=name
        )

        return self._adapter.post(
            url=api_path,
            json=params
        )


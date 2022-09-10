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
    
        if generate:
            if issuer == "" or account_name == "":
                error_msg = 'required issuer and account_name when generate is true, got "{issuer}", "{account_name}"'
                raise exceptions.ParamValidationError(
                    error_msg.format(
                        issuer=issuer,
                        account_name=account_name,
                    )
                )
            if skew not in ALLOWED_SKEW:
                error_msg = 'value can be either 0 or 1, got "{skew}"'
                raise exceptions.ParamValidationError(
                    error_msg.format(
                        skew=skew,
                    )
                )
        else:  
            if url == "":
                if not key:
                    error_msg = 'key is required if generate is false and url is empty'
                    raise exceptions.ParamValidationError(
                        error_msg
                    )
        if algorithm not in ALLOWED_ALGORITHMS:
            error_msg = 'Options include "SHA1", "SHA256" and "SHA512", got "{algorithm}"'
            raise exceptions.ParamValidationError(
                error_msg.format(
                    algorithm=algorithm,
                )
            )
        if digits not in ALLOWED_DIGITS:
            error_msg = 'This value can be either 0 or 1. Only used if generate is true, got "{digits}"'
            raise exceptions.ParamValidationError(
                error_msg.format(
                    digits=digits,
                )
            )
        if not qr_size >= 0:
            error_msg = 'qr_size should greater or equal to 0, got "{qr_size}"'
            raise exceptions.ParamValidationError(
                error_msg.format(
                    qr_size=qr_size,
                )
            )

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
        api_path = utils.format_url(
            "/v1/{mount_point}/keys/{name}",
            mount_point=mount_point,
            name=name
        )

        return self._adapter.get(url=api_path)
        pass

    def list_keys(
        self,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
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


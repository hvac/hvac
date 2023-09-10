"""Collection of classes for various Vault auth methods."""

import warnings

from hvac.api.auth_methods.approle import AppRole
from hvac.api.auth_methods.azure import Azure
from hvac.api.auth_methods.gcp import Gcp
from hvac.api.auth_methods.github import Github
from hvac.api.auth_methods.jwt import JWT
from hvac.api.auth_methods.kubernetes import Kubernetes
from hvac.api.auth_methods.ldap import Ldap
from hvac.api.auth_methods.userpass import Userpass
from hvac.api.auth_methods.legacy_mfa import LegacyMfa
from hvac.api.auth_methods.oidc import OIDC
from hvac.api.auth_methods.okta import Okta
from hvac.api.auth_methods.radius import Radius
from hvac.api.auth_methods.token import Token
from hvac.api.auth_methods.aws import Aws
from hvac.api.auth_methods.cert import Cert
from hvac.api.vault_api_category import VaultApiCategory
from hvac.utils import generate_method_deprecation_message

__all__ = (
    "AuthMethods",
    "AppRole",
    "Azure",
    "Gcp",
    "Github",
    "JWT",
    "Kubernetes",
    "Ldap",
    "Userpass",
    "LegacyMfa",
    "OIDC",
    "Okta",
    "Radius",
    "Token",
    "Aws",
    "Cert",
)


class AuthMethods(VaultApiCategory):
    """Auth Methods."""

    implemented_classes = [
        AppRole,
        Azure,
        Github,
        Gcp,
        JWT,
        Kubernetes,
        Ldap,
        Userpass,
        LegacyMfa,
        OIDC,
        Okta,
        Radius,
        Token,
        Aws,
        Cert,
    ]
    unimplemented_classes = [
        "AppId",
        "AliCloud",
        "Mfa",
    ]

    def __call__(self, *args, **kwargs):
        """Implement callable magic method for backwards compatibility.

        Older versions of hvac.Client had an auth method that has now been replaced with an "auth" property pointing to
        this class.
        """
        deprecation_message = generate_method_deprecation_message(
            to_be_removed_in_version="0.9.0",
            old_method_name="auth",
            method_name="login",
            module_name="adapters.Request",
        )
        warnings.warn(
            message=deprecation_message,
            category=DeprecationWarning,
            stacklevel=2,
        )

        return self._adapter.login(*args, **kwargs)

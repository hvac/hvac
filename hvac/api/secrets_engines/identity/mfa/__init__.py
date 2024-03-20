"""Collection of classes for various Vault identity MFA methods."""
from hvac.api.secrets_engines.identity.mfa.login_enforcement import LoginEnforcement
from hvac.api.secrets_engines.identity.mfa.duo import Duo
from hvac.api.secrets_engines.identity.mfa.okta import Okta
from hvac.api.secrets_engines.identity.mfa.pingid import PingID
from hvac.api.secrets_engines.identity.mfa.totp import TOTP
from hvac.api.vault_api_category import VaultApiCategory

__all__ = (
    "Duo",
    "LoginEnforcement",
    "MFA",
    "Okta",
    "PingID",
    "TOTP",
)


class MFA(
    VaultApiCategory,
    LoginEnforcement,
):
    implemented_classes = [
        Duo,
        LoginEnforcement,
        Okta,
        PingID,
        TOTP,
    ]
    unimplemented_classes = []

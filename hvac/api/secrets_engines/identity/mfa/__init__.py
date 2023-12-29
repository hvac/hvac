"""Collection of classes for various Vault identity MFA methods."""
from hvac.api.secrets_engines.identity.mfa.login_enforcement import LoginEnforcement
from hvac.api.vault_api_category import VaultApiCategory

__all__ = (
    "MFA",
)


class MFA(
    VaultApiCategory,
    LoginEnforcement,
):
    implemented_classes = [
        LoginEnforcement,
    ]
    unimplemented_classes = [
        "TOTP",
        "Okta",
        "Duo",
        "PingID",
    ]

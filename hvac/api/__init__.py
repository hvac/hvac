"""Collection of Vault API endpoint classes."""
from hvac.api import auth
from hvac.api.azure import Azure
from hvac.api import secrets_engines
from hvac.api.vault_api_base import VaultApiBase

__all__ = (
    'auth',
    'Azure',
    'secrets_engines',
    'VaultApiBase',
)

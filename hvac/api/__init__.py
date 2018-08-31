"""Collection of Vault API endpoint classes."""
from hvac.api import auth
from hvac.api import secrets_engines
from hvac.api.vault_api_base import VaultApiBase

__all__ = (
    'VaultApiBase',
    'auth',
    'secrets_engines',
)

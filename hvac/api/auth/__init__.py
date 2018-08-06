"""Collection of classes for various Vault auth methods."""

from hvac.api.auth.github import Github
from hvac.api.auth.mfa import Mfa

__all__ = (
    'Github',
    'Mfa',
)

"""Collection of classes for various Vault auth methods."""

from hvac.api.auth.github import Github
from hvac.api.auth.ldap import Ldap

__all__ = (
    'Github',
    'Ldap',
)

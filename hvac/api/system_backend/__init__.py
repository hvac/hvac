"""Collection of Vault system backend API endpoint classes."""
import logging

from hvac.api.system_backend.audit import Audit
from hvac.api.system_backend.auth import Auth
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin
from hvac.api.vault_api_category import VaultApiCategory

__all__ = (
    'Audit',
    'Auth',
    'SystemBackend',
    'SystemBackendMixin',
)


logger = logging.getLogger(__name__)


class SystemBackend(VaultApiCategory, Audit, Auth):
    implemented_classes = [
        Audit,
    ]
    unimplemented_classes = []

    def __init__(self, adapter):
        self._adapter = adapter

    def __getattr__(self, item):
        raise AttributeError

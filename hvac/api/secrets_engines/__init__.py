"""Vault secrets engines endpoints"""
from hvac.api.secrets_engines.aws import Aws
from hvac.api.secrets_engines.azure import Azure
from hvac.api.secrets_engines.gcp import Gcp
from hvac.api.secrets_engines.identity import Identity
from hvac.api.secrets_engines.kv import Kv
from hvac.api.secrets_engines.pki import Pki
from hvac.api.secrets_engines.kv_v1 import KvV1
from hvac.api.secrets_engines.kv_v2 import KvV2
from hvac.api.secrets_engines.transit import Transit
from hvac.api.secrets_engines.database import Database
from hvac.api.secrets_engines.consul import Consul
from hvac.api.vault_api_category import VaultApiCategory

__all__ = (
    'Aws',
    'Azure',
    'Gcp',
    'Identity',
    'Kv',
    'KvV1',
    'KvV2',
    'Pki',
    'Transit',
    'SecretsEngines',
    'Database'
)


class SecretsEngines(VaultApiCategory):
    """Secrets Engines."""

    implemented_classes = [
        Aws,
        Azure,
        Gcp,
        Identity,
        Kv,
        Pki,
        Transit,
        Database,
        Consul,
    ]
    unimplemented_classes = [
        'Ad',
        'AliCloud',
        'Azure',
        'GcpKms',
        'Nomad',
        'RabbitMq',
        'Ssh',
        'TOTP',
        'Cassandra',
        'MongoDb',
        'Mssql',
        'MySql',
        'PostgreSql',
    ]

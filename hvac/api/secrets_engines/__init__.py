"""
Vault secrets engines endpoints

"""
from hvac.api.secrets_engines.azure import Azure
from hvac.api.secrets_engines.kv import Kv
from hvac.api.secrets_engines.kv_v1 import KvV1
from hvac.api.secrets_engines.kv_v2 import KvV2
from hvac.api.secrets_engines.transit import Transit

__all__ = (
    'Azure',
    'Kv',
    'KvV1',
    'KvV2',
    'Transit',
)

"""Constants related to the hvac.Client class."""

from os import getenv

DEPRECATED_PROPERTIES = {
    "github": {
        "to_be_removed_in_version": "0.9.0",
        "client_property": "auth",
    },
    "ldap": {
        "to_be_removed_in_version": "0.9.0",
        "client_property": "auth",
    },
    "mfa": {
        "to_be_removed_in_version": "0.9.0",
        "client_property": "auth",
    },
    "kv": {
        "to_be_removed_in_version": "0.9.0",
        "client_property": "secrets",
    },
}

DEFAULT_URL = "http://localhost:8200"
VAULT_CACERT = getenv("VAULT_CACERT")
VAULT_CAPATH = getenv("VAULT_CAPATH")
VAULT_CLIENT_CERT = getenv("VAULT_CLIENT_CERT")
VAULT_CLIENT_KEY = getenv("VAULT_CLIENT_KEY")

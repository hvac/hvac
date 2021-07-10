#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Constants related to the hvac.Client class."""

from os import getenv

DEPRECATED_PROPERTIES = {}

DEFAULT_URL = "http://localhost:8200"
VAULT_CACERT = getenv("VAULT_CACERT")
VAULT_CAPATH = getenv("VAULT_CAPATH")
VAULT_CLIENT_CERT = getenv("VAULT_CLIENT_CERT")
VAULT_CLIENT_KEY = getenv("VAULT_CLIENT_KEY")

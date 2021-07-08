#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Constants related to the hvac.Client class."""

DEPRECATED_PROPERTIES = {
    'github': dict(
        to_be_removed_in_version='0.9.0',
        client_property='auth',
    ),
    'ldap': dict(
        to_be_removed_in_version='0.9.0',
        client_property='auth',
    ),
    'mfa': dict(
        to_be_removed_in_version='0.9.0',
        client_property='auth',
    ),
    'kv': dict(
        to_be_removed_in_version='0.9.0',
        client_property='secrets',
    ),
}

DEFAULT_URL = 'http://localhost:8200'
DEFAULT_BASE_URI = 'http://localhost:8200'

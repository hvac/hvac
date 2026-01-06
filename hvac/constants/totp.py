#!/usr/bin/env python
"""Constants related to the TOTP secrets engine."""

DEFAULT_MOUNT_POINT = "totp"
ALLOWED_ALGORITHMS = ['SHA1', 'SHA256', 'SHA512']
ALLOWED_DIGITS = [6, 8]
ALLOWED_SKEW = [0, 1]

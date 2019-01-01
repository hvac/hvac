#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Constants related to the AWS auth method and/or secrets engine."""

DEFAULT_MOUNT_POINT = 'aws'
ALLOWED_CREDS_ENDPOINTS = ['creds', 'sts']
ALLOWED_CREDS_TYPES = ['iam_user', 'assumed_role', 'federation_token']

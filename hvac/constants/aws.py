#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Constants related to the AWS auth method and/or secrets engine."""

DEFAULT_MOUNT_POINT = "aws"
ALLOWED_CREDS_ENDPOINTS = ["creds", "sts"]
ALLOWED_CREDS_TYPES = ["iam_user", "assumed_role", "federation_token"]
ALLOWED_IAM_ALIAS_TYPES = ["role_id", "unique_id", "full_arn"]
ALLOWED_EC2_ALIAS_TYPES = ["role_id", "instance_id", "image_id"]

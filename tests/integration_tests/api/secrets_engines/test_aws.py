#!/usr/bin/env python
import json
import logging
from unittest import TestCase

from parameterized import parameterized, param

from hvac.exceptions import ParamValidationError
from tests.utils import vault_version_lt
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestAws(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "aws-test"
    TEST_ROLE_NAME = "hvac-test-role"
    TEST_POLICY_DOCUMENT = {
        "Statement": [
            {"Action": "ec2:Describe*", "Effect": "Allow", "Resource": "*"},
        ],
        "Version": "2012-10-17",
    }

    def setUp(self):
        super().setUp()
        if "%s/" % self.TEST_MOUNT_POINT not in self.client.sys.list_auth_methods():
            self.client.sys.enable_secrets_engine(
                backend_type="aws",
                path=self.TEST_MOUNT_POINT,
            )

    def tearDown(self):
        self.client.sys.disable_secrets_engine(
            path=self.TEST_MOUNT_POINT,
        )
        super().tearDown()

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_configure_root_iam_credentials(
        self, label, credentials="", raises=None, exception_message=""
    ):
        access_key = "butts"
        secret_key = "secret-butts"
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.configure_root_iam_credentials(
                    access_key=access_key,
                    secret_key=secret_key,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            configure_response = self.client.secrets.aws.configure_root_iam_credentials(
                access_key=access_key,
                secret_key=secret_key,
                iam_endpoint="localhost",
                sts_endpoint="localhost",
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            self.assertEqual(
                first=bool(configure_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_configure_lease(
        self, label, lease="60s", lease_max="120s", raises=None, exception_message=""
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.configure_lease(
                    lease=lease,
                    lease_max=lease_max,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            configure_response = self.client.secrets.aws.configure_lease(
                lease=lease,
                lease_max=lease_max,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            self.assertEqual(
                first=bool(configure_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_read_lease(
        self,
        label,
        lease="60s",
        lease_max="120s",
        configure_first=True,
        raises=None,
        exception_message="",
    ):
        if configure_first:
            configure_response = self.client.secrets.aws.configure_lease(
                lease=lease,
                lease_max=lease_max,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.read_lease_config(
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_response = self.client.secrets.aws.read_lease_config(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_response: %s" % read_response)
            self.assertEqual(
                first=int(lease_max.replace("s", "")),
                second=self.convert_python_ttl_value_to_expected_vault_response(
                    ttl_value=read_response["data"]["lease_max"],
                ),
            )

    @parameterized.expand(
        [
            param(
                "success",
                policy_document={
                    "Statement": [
                        {"Action": "ec2:Describe*", "Effect": "Allow", "Resource": "*"},
                    ],
                    "Version": "2012-10-17",
                },
            ),
            param(
                "with policy_arns",
                policy_arns=["arn:aws:iam::aws:policy/AmazonVPCReadOnlyAccess"],
            ),
            param(
                "assumed_role with policy document",
                policy_document={
                    "Statement": [
                        {"Action": "ec2:Describe*", "Effect": "Allow", "Resource": "*"},
                    ],
                    "Version": "2012-10-17",
                },
                credential_type="assumed_role",
            ),
            param(
                "invalid credential type",
                credential_type="cat",
                raises=ParamValidationError,
                exception_message="invalid credential_type argument provided",
            ),
        ]
    )
    def test_create_or_update_role(
        self,
        label,
        credential_type="iam_user",
        policy_document=None,
        default_sts_ttl=None,
        max_sts_ttl=None,
        role_arns=None,
        policy_arns=None,
        raises=None,
        exception_message="",
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.create_or_update_role(
                    name=self.TEST_ROLE_NAME,
                    credential_type=credential_type,
                    policy_document=policy_document,
                    default_sts_ttl=default_sts_ttl,
                    max_sts_ttl=max_sts_ttl,
                    role_arns=role_arns,
                    policy_arns=policy_arns,
                    legacy_params=vault_version_lt("0.11.0"),
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            role_response = self.client.secrets.aws.create_or_update_role(
                name=self.TEST_ROLE_NAME,
                credential_type=credential_type,
                policy_document=policy_document,
                default_sts_ttl=default_sts_ttl,
                max_sts_ttl=max_sts_ttl,
                role_arns=role_arns,
                policy_arns=policy_arns,
                legacy_params=vault_version_lt("0.11.0"),
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("role_response: %s" % role_response)

            self.assertEqual(
                first=bool(role_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_read_role(
        self, label, configure_first=True, raises=None, exception_message=""
    ):
        if configure_first:
            self.client.secrets.aws.create_or_update_role(
                name=self.TEST_ROLE_NAME,
                credential_type="iam_user",
                policy_document=self.TEST_POLICY_DOCUMENT,
                legacy_params=vault_version_lt("0.11.0"),
                mount_point=self.TEST_MOUNT_POINT,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.read_role(
                    name=self.TEST_ROLE_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_role_response = self.client.secrets.aws.read_role(
                name=self.TEST_ROLE_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_role_response: %s" % read_role_response)
            if vault_version_lt("0.11.0"):
                self.assertDictEqual(
                    d1=json.loads(read_role_response["data"]["policy"]),
                    d2=self.TEST_POLICY_DOCUMENT,
                )
            # https://github.com/hashicorp/vault/commit/2dcd0aed2a242f53dae03318b4d68693f7d92b81
            elif vault_version_lt("1.0.2"):
                self.assertEqual(
                    first=read_role_response["data"]["credential_types"],
                    second=["iam_user"],
                )
            else:
                self.assertEqual(
                    first=read_role_response["data"]["credential_type"],
                    second="iam_user",
                )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_list_roles(
        self, label, configure_first=True, raises=None, exception_message=""
    ):
        if configure_first:
            self.client.secrets.aws.create_or_update_role(
                name=self.TEST_ROLE_NAME,
                credential_type="iam_user",
                policy_document=self.TEST_POLICY_DOCUMENT,
                legacy_params=vault_version_lt("0.11.0"),
                mount_point=self.TEST_MOUNT_POINT,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.list_roles(
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            list_roles_response = self.client.secrets.aws.list_roles(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("list_roles_response: %s" % list_roles_response)
            self.assertEqual(
                first=list_roles_response["data"]["keys"],
                second=[self.TEST_ROLE_NAME],
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_delete_role(
        self, label, configure_first=True, raises=None, exception_message=""
    ):
        if configure_first:
            self.client.secrets.aws.create_or_update_role(
                name=self.TEST_ROLE_NAME,
                credential_type="iam_user",
                policy_document=self.TEST_POLICY_DOCUMENT,
                legacy_params=vault_version_lt("0.11.0"),
                mount_point=self.TEST_MOUNT_POINT,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.delete_role(
                    name=self.TEST_ROLE_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            delete_role_response = self.client.secrets.aws.delete_role(
                name=self.TEST_ROLE_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("delete_role_response: %s" % delete_role_response)
            self.assertEqual(
                first=bool(delete_role_response),
                second=True,
            )

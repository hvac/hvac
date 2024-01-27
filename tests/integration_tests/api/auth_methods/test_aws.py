from unittest import TestCase

from parameterized import parameterized, param

from hvac import exceptions
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestAws(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "aws-test"

    def setUp(self):
        super().setUp()
        if "%s/" % self.TEST_MOUNT_POINT not in self.client.sys.list_auth_methods():
            self.client.sys.enable_auth_method(
                method_type="aws",
                path=self.TEST_MOUNT_POINT,
            )

    def tearDown(self):
        super().tearDown()
        self.client.sys.disable_auth_method(
            path=self.TEST_MOUNT_POINT,
        )

    @parameterized.expand(
        [
            param(
                "no params",
            ),
            param(
                "valid iam metadata input 1",
                iam_metadata="default",
            ),
            param(
                "valid iam metadata input 2",
                iam_metadata=["auth_type", "client_arn", "inferred_aws_region"],
            ),
            param(
                "valid ec2 metadata input 1",
                ec2_metadata=["region", "ami_id", "account_id"],
            ),
            param("valid ec2 metadata input 2", ec2_metadata="default"),
            param("valid ec2 alias input 1", ec2_alias="instance_id"),
            param("valid ec2 alias input 2", ec2_alias="role_id"),
            param("valid iam alias input 1", iam_alias="full_arn"),
            param("valid iam alias input 2", iam_alias="role_id"),
            param(
                "valid combination",
                ec2_metadata=["region", "instance_id", "auth_type"],
                iam_metadata=[
                    "inferred_entity_type",
                    "inferred_entity_id",
                    "canonical_arn",
                    "client_user_id",
                    "account_id",
                ],
                ec2_alias="image_id",
                iam_alias="unique_id",
            ),
        ]
    )
    def test_configure_identity_integration_succeeds(
        self, label, ec2_metadata="", iam_metadata="", ec2_alias=None, iam_alias=None
    ):
        configure_response = self.client.auth.aws.configure_identity_integration(
            mount_point=self.TEST_MOUNT_POINT,
            ec2_metadata=ec2_metadata,
            iam_metadata=iam_metadata,
            ec2_alias=ec2_alias,
            iam_alias=iam_alias,
        )
        self.assertEqual(
            first=bool(configure_response),
            second=True,
        )

    @parameterized.expand(
        [
            param(
                "invalid ec2 metadata",
                raises=exceptions.InvalidRequest,
                exception_message="contains an unavailable field, please select from",
                ec2_metadata="something invalid",
            ),
            param(
                "invalid iam metadata",
                iam_metadata="something invalid",
                raises=exceptions.InvalidRequest,
                exception_message="contains an unavailable field, please select from",
            ),
            param(
                "invalid iam alias",
                iam_alias="something invalid",
                raises=exceptions.ParamValidationError,
                exception_message="invalid iam alias type provided",
            ),
            param(
                "invalid ec2 alias",
                ec2_alias="something invalid",
                raises=exceptions.ParamValidationError,
                exception_message="invalid ec2 alias type provided",
            ),
        ]
    )
    def test_configure_identity_integration_fails(
        self,
        label,
        raises,
        exception_message,
        ec2_metadata=None,
        iam_metadata=None,
        ec2_alias=None,
        iam_alias=None,
    ):
        with self.assertRaises(raises) as cm:
            self.client.auth.aws.configure_identity_integration(
                mount_point=self.TEST_MOUNT_POINT,
                ec2_metadata=ec2_metadata,
                iam_metadata=iam_metadata,
                ec2_alias=ec2_alias,
                iam_alias=iam_alias,
            )
        self.assertIn(
            member=exception_message,
            container=str(cm.exception),
        )

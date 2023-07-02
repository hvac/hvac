import logging
from unittest import TestCase
from unittest import skipIf

from parameterized import parameterized

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(
    utils.vault_version_lt("0.11.0"),
    "Azure secret engine not available before Vault version 0.11.0",
)
class TestAzure(HvacIntegrationTestCase, TestCase):
    TENANT_ID = "00000000-0000-0000-0000-000000000000"
    SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
    DEFAULT_MOUNT_POINT = "azure-integration-test"

    def setUp(self):
        super().setUp()
        self.client.sys.enable_secrets_engine(
            backend_type="azure",
            path=self.DEFAULT_MOUNT_POINT,
        )

    def tearDown(self):
        self.client.sys.disable_secrets_engine(path=self.DEFAULT_MOUNT_POINT)
        super().tearDown()

    @parameterized.expand(
        [
            ("no parameters",),
            ("valid environment argument", "AzureUSGovernmentCloud"),
            (
                "invalid environment argument",
                "AzureCityKity",
                exceptions.ParamValidationError,
                "invalid environment argument provided",
            ),
        ]
    )
    def test_configure_and_read_configuration(
        self, test_label, environment=None, raises=False, exception_message=""
    ):
        configure_arguments = {
            "subscription_id": self.SUBSCRIPTION_ID,
            "tenant_id": self.TENANT_ID,
            "mount_point": self.DEFAULT_MOUNT_POINT,
        }
        if environment is not None:
            configure_arguments["environment"] = environment
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.azure.configure(**configure_arguments)
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            configure_response = self.client.secrets.azure.configure(
                **configure_arguments
            )
            logging.debug("configure_response: %s" % configure_response)
            read_configuration_response = self.client.secrets.azure.read_config(
                mount_point=self.DEFAULT_MOUNT_POINT,
            )
            logging.debug(
                "read_configuration_response: %s" % read_configuration_response
            )
            # raise Exception()
            self.assertEqual(
                first=self.SUBSCRIPTION_ID,
                second=read_configuration_response["subscription_id"],
            )
            self.assertEqual(
                first=self.TENANT_ID,
                second=read_configuration_response["tenant_id"],
            )
            if environment is not None:
                self.assertEqual(
                    first=environment,
                    second=read_configuration_response["environment"],
                )

    @parameterized.expand(
        [
            ("create and then delete config",),
        ]
    )
    def test_delete_config(self, test_label):
        configure_response = self.client.secrets.azure.configure(
            subscription_id=self.SUBSCRIPTION_ID,
            tenant_id=self.TENANT_ID,
            mount_point=self.DEFAULT_MOUNT_POINT,
        )
        logging.debug("configure_response: %s" % configure_response)
        self.client.secrets.azure.delete_config(
            mount_point=self.DEFAULT_MOUNT_POINT,
        )
        read_configuration_response = self.client.secrets.azure.read_config(
            mount_point=self.DEFAULT_MOUNT_POINT,
        )
        logging.debug("read_configuration_response: %s" % read_configuration_response)
        read_expected_response = {
            "client_id": "",
            "environment": "",
            "subscription_id": "",
            "tenant_id": "",
        }
        if utils.vault_version_ge("1.9.0"):
            read_expected_response["root_password_ttl"] = 0
            if utils.vault_version_lt("1.12.0"):
                read_expected_response["use_microsoft_graph_api"] = False
        self.assertEqual(
            first=read_expected_response,
            second=read_configuration_response,
        )

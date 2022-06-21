import logging
from unittest import TestCase

from parameterized import param, parameterized

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestGcp(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "test-gcp"
    TEST_ROLESET_NAME = "hvac-roleset"
    TEST_PROJECT_ID = "test-hvac"

    def setUp(self):
        super().setUp()
        self.client.sys.enable_secrets_engine(
            backend_type="gcp",
            path=self.TEST_MOUNT_POINT,
        )

    def tearDown(self):
        self.client.sys.disable_secrets_engine(path=self.TEST_MOUNT_POINT)
        super().tearDown()

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_write_config(
        self, label, max_ttl=3600, raises=False, exception_message=""
    ):
        credentials = utils.load_config_file("example.jwt.json")
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.gcp.configure(
                    credentials=credentials,
                    max_ttl=max_ttl,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            configure_response = self.client.secrets.gcp.configure(
                credentials=credentials,
                max_ttl=max_ttl,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            self.assertEqual(
                first=bool(configure_response),
                second=True,
            )
            read_configuration_response = self.client.secrets.gcp.read_config(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug(
                "read_configuration_response: %s" % read_configuration_response
            )
            self.assertEqual(
                first=read_configuration_response["data"]["max_ttl"],
                second=max_ttl,
            )

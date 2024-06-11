import logging
from unittest import TestCase

from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestWrapping(HvacIntegrationTestCase, TestCase):
    TEST_AUTH_METHOD_TYPE = "approle"
    TEST_AUTH_METHOD_PATH = "test-approle"

    def test_unwrap(self):
        self.client.sys.enable_auth_method(
            method_type=self.TEST_AUTH_METHOD_TYPE,
            path=self.TEST_AUTH_METHOD_PATH,
        )

        self.client.write(
            path=f"auth/{self.TEST_AUTH_METHOD_PATH}/role/testrole",
        )
        result = self.client.write(
            path="auth/{path}/role/testrole/secret-id".format(
                path=self.TEST_AUTH_METHOD_PATH
            ),
            wrap_ttl="10s",
        )
        self.assertIn("token", result["wrap_info"])

        unwrap_response = self.client.sys.unwrap(result["wrap_info"]["token"])
        logging.debug("unwrap_response: %s" % unwrap_response)
        self.assertIn(member="secret_id_accessor", container=unwrap_response["data"])
        self.assertIn(member="secret_id", container=unwrap_response["data"])

    def test_wrap(self):
        ttl = 180

        wrap_response = self.client.sys.wrap(payload={"test": "test"}, ttl=ttl)
        logging.debug("wrap_response: %s" % wrap_response)
        self.assertIn("token", wrap_response["wrap_info"])
        self.assertEqual(wrap_response["wrap_info"]["ttl"], ttl)

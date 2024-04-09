import logging
from unittest import TestCase

from parameterized import parameterized, param

from hvac import exceptions
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestTools(HvacIntegrationTestCase, TestCase):
    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_generate_random_bytes(
        self, label, n_bytes=32, raises=False, exception_message=""
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.sys.generate_random_bytes(
                    n_bytes=n_bytes,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            gen_bytes_response = self.client.sys.generate_random_bytes(
                n_bytes=n_bytes,
            )
            logging.debug("gen_data_key_response: %s" % gen_bytes_response)
            self.assertIn(
                member="random_bytes",
                container=gen_bytes_response["data"],
            )

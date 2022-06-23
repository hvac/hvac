import logging
from unittest import TestCase

from parameterized import parameterized, param
from tests.utils import create_client
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestHealth(HvacIntegrationTestCase, TestCase):
    enable_vault_ha = True

    def tearDown(self):
        # If one of our test cases left the Vault cluster sealed, unseal it here.
        self.manager.unseal()
        super().tearDown()

    @parameterized.expand(
        [
            param(
                "default params",
            ),
            param(
                "unsealed standby node HEAD method",
                use_standby_node=True,
                method="HEAD",
                expected_status_code=429,
                ha_required=True,
            ),
            param(
                "unsealed standby node GET method",
                use_standby_node=True,
                method="GET",
                expected_status_code=429,
                ha_required=True,
            ),
            param(
                "sealed standby node HEAD method",
                use_standby_node=True,
                method="HEAD",
                expected_status_code=503,
                seal_first=True,
                ha_required=True,
            ),
            param(
                "sealed standby node GET method",
                use_standby_node=True,
                method="GET",
                expected_status_code=503,
                seal_first=True,
                ha_required=True,
            ),
            param("GET method", method="GET"),
        ]
    )
    def test_read_health_status(
        self,
        label,
        method="HEAD",
        use_standby_node=False,
        expected_status_code=200,
        seal_first=False,
        ha_required=False,
    ):
        """Test the Health system backend class's "read_health_status" method.

        :param label: Label for a given parameterized test case.
        :type label: str
        :param method: HTTP method to use when invoking the method under test (GET or HEAD available).
        :type method: str
        :param use_standby_node: If True, send the request to a standby Vault node address
        :type use_standby_node: bool
        :param expected_status_code: The status code code expected in the response from Vault.
        :type expected_status_code: int
        :param seal_first: If True, seal the Vault node(s) before running the test cases.
        :type seal_first: bool
        :param ha_required: If True, skip the test case when consul / a HA Vault integration cluster is unavailable.
        :type ha_required: bool
        """
        if ha_required and not self.enable_vault_ha:
            # Conditional to allow folks to run this test class without requiring consul to be installed locally.
            self.skipTest("Skipping test case, Vault HA required but not available.")
        if seal_first:
            # Standby nodes can't be sealed directly.
            # I.e.: "vault cannot seal when in standby mode; please restart instead"
            self.manager.restart_vault_cluster()

        # Grab a Vault node address for our desired standby status and create a one-off client configured for that address.
        vault_addr = self.get_vault_addr_by_standby_status(
            standby_status=use_standby_node
        )
        logging.debug("vault_addr being used: %s" % vault_addr)
        client = create_client(url=vault_addr)

        read_status_response = client.sys.read_health_status(
            method=method,
        )
        logging.debug("read_status_response: %s" % read_status_response)
        if expected_status_code == 200:
            self.assertTrue(read_status_response)
        else:
            self.assertEqual(
                first=read_status_response.status_code,
                second=expected_status_code,
            )
        if method != "HEAD":
            if not isinstance(read_status_response, dict):
                read_status_response = read_status_response.json()
            self.assertTrue(expr=read_status_response["initialized"])

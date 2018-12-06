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
        super(TestHealth, self).tearDown()

    @parameterized.expand([
        param(
            'default params',
        ),
        param(
            'unsealed standby node',
            vault_addr='https://127.0.0.1:8199',
            method='HEAD',
            expected_status_code=429,
            ha_required=True,
        ),
        param(
            'sealed standby node',
            vault_addr='https://127.0.0.1:8199',
            method='GET',
            expected_status_code=503,
            seal_first=True,
            ha_required=True,
        ),
        param(
            'GET method',
            method='GET'
        ),
    ])
    def test_read_health_status(self, label, method='HEAD', vault_addr=None, expected_status_code=200, seal_first=False, ha_required=False):
        """Test the Health system backend class's "read_health_status" method.

        :param label: Label for a given parameterized test case.
        :type label: str
        :param method: HTTP method to use when invoking the method under test (GET or HEAD available).
        :type method: str
        :param vault_addr: The address of the Vault node to send the request to.
        :type vault_addr: str
        :param expected_status_code: The status code code expected in the response from Vault.
        :type expected_status_code: int
        :param seal_first: If True, seal the Vault node(s) before running the test cases.
        :type seal_first: bool
        :param ha_required: If True, skip the test case when consul / a HA Vault integration cluster is unavailable.
        :type ha_required: bool
        """
        if ha_required and not self.enable_vault_ha:
            # Conditional to allow folks to run this test class without requiring consul to be installed locally.
            self.skipTest('Skipping test case, Vault HA required but not available.')
        if vault_addr is not None:
            client = create_client(url=vault_addr)
        else:
            client = self.client
        if seal_first:
            # Standby nodes can't be sealed directly.
            # I.e.: "vault cannot seal when in standby mode; please restart instead"
            self.manager.restart_vault_cluster()
        logging.debug('vault processes: %s' % self.manager._processes)
        read_status_response = client.sys.read_health_status(
            method=method,
        )
        logging.debug('read_status_response: %s' % read_status_response)
        if method == 'HEAD':
            self.assertEqual(
                first=read_status_response.status_code,
                second=expected_status_code,
            )
        else:
            self.assertTrue(
                expr=read_status_response['initialized']
            )

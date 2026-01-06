from unittest import TestCase

from tests.utils import create_client
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestGetLeader(HvacIntegrationTestCase, TestCase):
    enable_vault_ha = True

    def tearDown(self):
        # If one of our test cases left the Vault cluster sealed, unseal it here.
        self.manager.unseal()
        super().tearDown()

    def test_get_leader(
        self, use_standby_node=True, seal_first=False, ha_required=True
    ):
        """Test the system backend class's "get_leader" method.

        :param use_standby_node: If True, send the request to a standby Vault node address
        :type use_standby_node: bool
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

        # Set a fake Vault address to ensure that the client is forced to use the address we provide.
        fake_vault_addr = "https://does.not.exist:8200"
        # Grab a Vault node address for our desired standby status and create a one-off client configured for that address.
        standby_vault_addr = self.get_vault_addr_by_standby_status(standby_status=True)

        leader_vault_addr = self.get_vault_addr_by_standby_status(standby_status=False)

        cluster_url = [fake_vault_addr, standby_vault_addr, leader_vault_addr]
        client = create_client(url=standby_vault_addr, cluster_url=cluster_url)
        leader = client.sys.get_leader()

        self.assertEqual(first=leader_vault_addr, second=leader)

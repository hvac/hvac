from unittest import TestCase

from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestLeader(HvacIntegrationTestCase, TestCase):
    def test_read_health_status(self):
        self.assertIn(
            member="ha_enabled",
            container=self.client.sys.read_leader_status(),
        )

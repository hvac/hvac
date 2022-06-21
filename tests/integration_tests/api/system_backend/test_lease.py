import logging
from unittest import TestCase

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestLease(HvacIntegrationTestCase, TestCase):
    def setUp(self):
        super().setUp()
        # Set up a test pki backend and issue a cert against some role so we.
        utils.configure_pki(client=self.client)

    def tearDown(self):
        # Reset integration test state.
        utils.disable_pki(client=self.client)
        super().tearDown()

    def test_read_lease(self):
        pki_issue_response = self.client.write(
            path="pki/issue/my-role",
            common_name="test.hvac.com",
        )

        # Read the lease of our test cert that was just issued.
        read_lease_response = self.client.sys.read_lease(
            lease_id=pki_issue_response["lease_id"],
        )
        logging.debug("read_lease_response: %s" % read_lease_response)

        # Validate we received the expected lease ID back in our response.
        self.assertEqual(
            first=pki_issue_response["lease_id"],
            second=read_lease_response["data"]["id"],
        )

    def test_list_leases(self):
        self.client.write(
            path="pki/issue/my-role",
            common_name="test.hvac.com",
        )

        # List the lease of our test cert that was just issued.
        list_leases_response = self.client.sys.list_leases(
            prefix="pki",
        )
        logging.debug("list_leases_response: %s" % list_leases_response)
        self.assertIn(
            member="issue/",
            container=list_leases_response["data"]["keys"],
        )

    def test_revoke_lease(self):
        pki_issue_response = self.client.write(
            path="pki/issue/my-role",
            common_name="test.hvac.com",
        )

        # Revoke the lease of our test cert that was just issued.
        revoke_lease_response = self.client.sys.revoke_lease(
            lease_id=pki_issue_response["lease_id"],
        )
        logging.debug("revoke_lease_response: %s" % revoke_lease_response)

        self.assertEqual(
            first=bool(revoke_lease_response),
            second=True,
        )
        with self.assertRaises(exceptions.InvalidPath):
            self.client.sys.list_leases(
                prefix="pki",
            )

    def test_revoke_prefix(self):
        pki_issue_response = self.client.write(
            path="pki/issue/my-role",
            common_name="test.hvac.com",
        )

        # Revoke the lease prefix of our test cert that was just issued.
        revoke_prefix_response = self.client.sys.revoke_prefix(
            prefix=pki_issue_response["lease_id"],
        )
        logging.debug("revoke_prefix_response: %s" % revoke_prefix_response)

        self.assertEqual(
            first=bool(revoke_prefix_response),
            second=True,
        )

    def test_revoke_force(self):
        pki_issue_response = self.client.write(
            path="pki/issue/my-role",
            common_name="test.hvac.com",
        )

        # Force revoke the lease of our test cert that was just issued.
        revoke_force_response = self.client.sys.revoke_force(
            pki_issue_response["lease_id"]
        )
        logging.debug("revoke_force_response: %s" % revoke_force_response)

        self.assertEqual(
            first=bool(revoke_force_response),
            second=True,
        )

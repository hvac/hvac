import logging
from unittest import TestCase, skipIf

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(not utils.is_enterprise(), "Namespaces only supported with Enterprise Vault")
class TestNamespace(HvacIntegrationTestCase, TestCase):
    def test_list_namespaces(self):
        test_namespace_name = "python-hvac"
        create_namespace_response = self.client.sys.create_namespace(
            path=test_namespace_name
        )
        logging.debug("create_namespace_response: %s" % create_namespace_response)

        # Verify the namespace we just created is retrievable in a listing.
        list_namespaces_response = self.client.sys.list_namespaces()
        logging.debug("list_namespaces_response: %s" % list_namespaces_response)
        self.assertIn(
            member="%s/" % test_namespace_name,
            container=list_namespaces_response["data"]["keys"],
        )

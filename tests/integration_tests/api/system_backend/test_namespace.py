import logging
from unittest import TestCase, skipIf

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(not utils.is_enterprise(), "Namespaces only supported with Enterprise Vault")
class TestNamespace(HvacIntegrationTestCase, TestCase):
    def test_read_namespace(self):
        test_namespace_name = "python-hvac-read"
        self.client.sys.create_namespace(path=test_namespace_name)

        read_namespace_response = self.client.sys.read_namespace(
            path=test_namespace_name
        )
        logging.debug("read_namespace_response: %s" % read_namespace_response)
        self.assertEqual(
            first="%s/" % test_namespace_name,
            second=read_namespace_response["data"]["path"],
        )

        self.client.sys.delete_namespace(path=test_namespace_name)

    @skipIf(
        utils.vault_version_lt("1.12.0"),
        "PATCH /sys/namespaces support added in Vault 1.12.0",
    )
    def test_patch_namespace(self):
        test_namespace_name = "python-hvac-patch"
        self.client.sys.create_namespace(path=test_namespace_name)

        self.client.sys.patch_namespace(
            path=test_namespace_name,
            custom_metadata={"env": "test"},
        )

        read_response = self.client.sys.read_namespace(path=test_namespace_name)
        logging.debug("read_response: %s" % read_response)
        self.assertEqual(
            first={"env": "test"},
            second=read_response["data"]["custom_metadata"],
        )

        self.client.sys.delete_namespace(path=test_namespace_name)

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

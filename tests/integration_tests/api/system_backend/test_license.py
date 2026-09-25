import logging
from unittest import TestCase, skipIf

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(
    not utils.is_enterprise() or utils.vault_version_lt("1.10.0"),
    "License status requires Enterprise Vault 1.10+",
)
class TestLicense(HvacIntegrationTestCase, TestCase):
    def test_read_license_status(self):
        read_license_status_response = self.client.sys.read_license_status()
        logging.debug("read_license_status_response: %s" % read_license_status_response)
        data = read_license_status_response.get("data", {})
        self.assertIn("autoloaded_license", data)
        license_info = data.get("license", {})
        self.assertTrue(license_info.get("license_id"))

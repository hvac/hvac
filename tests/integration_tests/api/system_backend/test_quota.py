import logging
from unittest import TestCase, skipIf

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestQuota(HvacIntegrationTestCase, TestCase):
    def setUp(self):
        super().setUp()
        self.client.sys.enable_secrets_engine(backend_type="kv", path="test")

    def tearDown(self):
        self.client.sys.disable_secrets_engine(path="test")
        super().tearDown()

    @skipIf(
        utils.vault_version_ge("1.12.0"),
        "Older versions of Vault return different JSON structure",
    )
    def test_create_quota_old(self):
        quota_dict = {
            "block_interval": "600",
            "interval": "600",
            "name": "test-quota",
            "path": "test/*/",
            "rate": 100,
            "type": "rate-limit",
        }

        # Create quota
        create_or_update_quota_response = self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=quota_dict["rate"],
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )
        logging.debug(
            "create_or_update_quota_response: %s" % create_or_update_quota_response
        )

        # API takes str arg for interval and block_interval but returns attribute in int num of seconds
        quota_dict["block_interval"] = int(quota_dict["block_interval"])
        quota_dict["interval"] = int(quota_dict["interval"])

        self.assertEqual(
            first=quota_dict,
            second=self.client.sys.read_quota(quota_dict["name"])["data"],
        )

        with self.assertRaises(exceptions.InvalidRequest):
            self.client.sys.create_or_update_quota(
                name="test-invalid-path", rate=101, path="/not-exist"
            )

    @skipIf(
        utils.vault_version_lt("1.12.0") or utils.vault_version_ge("1.15.0"),
        "Newer version of quota JSON changes path structure and adds role. Route only works on enterprise from 1.15 onwards",
    )
    def test_create_quota(self):
        quota_dict = {
            "block_interval": "600",
            "interval": "600",
            "name": "test-quota",
            "path": "test/*",
            "rate": 100,
            "role": "",
            "type": "rate-limit",
        }

        # Create quota
        create_or_update_quota_response = self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=quota_dict["rate"],
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )
        logging.debug(
            "create_or_update_quota_response: %s" % create_or_update_quota_response
        )

        # API takes str arg for interval and block_interval but returns attribute in int num of seconds
        quota_dict["block_interval"] = int(quota_dict["block_interval"])
        quota_dict["interval"] = int(quota_dict["interval"])

        self.assertEqual(
            first=quota_dict,
            second=self.client.sys.read_quota(quota_dict["name"])["data"],
        )

        with self.assertRaises(exceptions.InvalidRequest):
            self.client.sys.create_or_update_quota(
                name="test-invalid-path", rate=101, path="/not-exist"
            )

    @skipIf(
        utils.vault_version_ge("1.12.0"),
        "Older versions of Vault return different JSON structure",
    )
    def test_update_quota_old(self):
        quota_dict = {
            "block_interval": "600",
            "interval": "600",
            "name": "test-quota",
            "path": "test/*/",
            "rate": 100,
            "type": "rate-limit",
        }

        # Create quota
        self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=101,
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )

        # Update quota
        self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=quota_dict["rate"],
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )

        # API takes str arg for interval and block_interval but returns attribute in int num of seconds
        quota_dict["block_interval"] = int(quota_dict["block_interval"])
        quota_dict["interval"] = int(quota_dict["interval"])

        self.assertEqual(
            first=quota_dict,
            second=self.client.sys.read_quota(quota_dict["name"])["data"],
        )

    @skipIf(
        utils.vault_version_lt("1.12.0") or utils.vault_version_ge("1.15.0"),
        "Newer version of quota JSON changes path structure and adds role. Route only works on enterprise from 1.15 onwards",
    )
    def test_update_quota(self):
        quota_dict = {
            "block_interval": "600",
            "interval": "600",
            "name": "test-quota",
            "path": "test/*",
            "rate": 100,
            "role": "",
            "type": "rate-limit",
        }

        # Create quota
        self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=101,
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )

        # Update quota
        self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=quota_dict["rate"],
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )

        # API takes str arg for interval and block_interval but returns attribute in int num of seconds
        quota_dict["block_interval"] = int(quota_dict["block_interval"])
        quota_dict["interval"] = int(quota_dict["interval"])

        self.assertEqual(
            first=quota_dict,
            second=self.client.sys.read_quota(quota_dict["name"])["data"],
        )

    @skipIf(
        utils.vault_version_ge("1.12.0"),
        "Older versions of Vault return different JSON structure",
    )
    def test_read_quota_old(self):
        quota_dict = {
            "block_interval": "600",
            "interval": "600",
            "name": "test-quota",
            "path": "test/*/",
            "rate": 100,
            "type": "rate-limit",
        }

        self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=quota_dict["rate"],
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )

        # Read the quota that was just created
        read_quota_response = self.client.sys.read_quota(
            name=quota_dict["name"],
        )
        logging.debug("read_quota_response: %s" % read_quota_response)

        # API takes str arg for interval and block_interval but returns attribute in int num of seconds
        quota_dict["block_interval"] = int(quota_dict["block_interval"])
        quota_dict["interval"] = int(quota_dict["interval"])

        self.assertEqual(
            first=quota_dict,
            second=read_quota_response["data"],
        )

    @skipIf(
        utils.vault_version_lt("1.12.0") or utils.vault_version_ge("1.15.0"),
        "Newer version of quota JSON changes path structure and adds role. Route only works on enterprise from 1.15 onwards",
    )
    def test_read_quota(self):
        quota_dict = {
            "block_interval": "600",
            "interval": "600",
            "name": "test-quota",
            "path": "test/*",
            "rate": 100,
            "role": "",
            "type": "rate-limit",
        }

        self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=quota_dict["rate"],
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )

        # Read the quota that was just created
        read_quota_response = self.client.sys.read_quota(
            name=quota_dict["name"],
        )
        logging.debug("read_quota_response: %s" % read_quota_response)

        # API takes str arg for interval and block_interval but returns attribute in int num of seconds
        quota_dict["block_interval"] = int(quota_dict["block_interval"])
        quota_dict["interval"] = int(quota_dict["interval"])

        self.assertEqual(
            first=quota_dict,
            second=read_quota_response["data"],
        )

    @skipIf(
        utils.vault_version_lt("1.12.0") or utils.vault_version_ge("1.15.0"),
        "Newer version of quota JSON changes path structure and adds role. Route only works on enterprise from 1.15 onwards",
    )
    def test_list_quotas(self):
        quota_dict = {
            "block_interval": "600",
            "interval": "600",
            "name": "test-quota",
            "path": "test/*",
            "rate": 100,
            "role": "",
            "type": "rate-limit",
        }

        self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=quota_dict["rate"],
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )

        list_quotas_response = self.client.sys.list_quotas()
        logging.debug("list_quotas_response: %s" % list_quotas_response)

        # API takes str arg for interval and block_interval but returns attribute in int num of seconds
        quota_dict["block_interval"] = int(quota_dict["block_interval"])
        quota_dict["interval"] = int(quota_dict["interval"])

        self.assertIn(
            member="test-quota",
            container=list_quotas_response["data"]["keys"],
        )

    @skipIf(
        utils.vault_version_ge("1.12.0"),
        "Older versions of Vault return different JSON structure",
    )
    def test_delete_quota_old(self):
        quota_dict = {
            "block_interval": "600",
            "interval": "600",
            "name": "test-quota",
            "path": "test/*/",
            "rate": 100,
            "type": "rate-limit",
        }

        self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=quota_dict["rate"],
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )

        # Delete the quota that was just created
        delete_quota_response = self.client.sys.delete_quota(
            name=quota_dict["name"],
        )

        logging.debug("delete_quota_response: %s" % delete_quota_response)

        with self.assertRaises(exceptions.InvalidPath):
            self.client.sys.read_quota(
                name=quota_dict["name"],
            )

    @skipIf(
        utils.vault_version_lt("1.12.0") or utils.vault_version_ge("1.15.0"),
        "Newer version of quota JSON changes path structure and adds role. Route only works on enterprise from 1.15 onwards",
    )
    def test_delete_quota(self):
        quota_dict = {
            "block_interval": "600",
            "interval": "600",
            "name": "test-quota",
            "path": "test/*",
            "rate": 100,
            "role": "",
            "type": "rate-limit",
        }

        self.client.sys.create_or_update_quota(
            name=quota_dict["name"],
            rate=quota_dict["rate"],
            path=quota_dict["path"],
            interval=quota_dict["interval"],
            block_interval=quota_dict["block_interval"],
        )

        # Delete the quota that was just created
        delete_quota_response = self.client.sys.delete_quota(
            name=quota_dict["name"],
        )

        logging.debug("delete_quota_response: %s" % delete_quota_response)

        with self.assertRaises(exceptions.InvalidPath):
            self.client.sys.read_quota(
                name=quota_dict["name"],
            )

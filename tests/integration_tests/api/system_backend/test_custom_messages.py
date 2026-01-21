import logging
from datetime import datetime, timedelta, timezone
from unittest import TestCase, skipIf

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestCustomMessages(HvacIntegrationTestCase, TestCase):
    def setUp(self):
        super().setUp()
        self.custom_message_id = None

    def tearDown(self):
        # Clean up any custom messages created during tests
        if self.custom_message_id:
            try:
                self.client.sys.delete_custom_messages(id=self.custom_message_id)
            except exceptions.InvalidPath:
                pass
        super().tearDown()

    @skipIf(
        not utils.vault_version_ge("1.16.0") or not utils.is_enterprise(),
        "Custom messages only supported in Enterprise Vault version 1.16.0 or greater",
    )
    def test_create_custom_message(self):
        current_time = datetime.now(timezone.utc)
        start_time_str = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = current_time + timedelta(minutes=3)
        end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        message_data = {
            "title": "Test Message",
            "message": "This is a test custom message.",
            "start_time": start_time_str,
            "end_time": end_time_str,
        }

        create_response = self.client.sys.create_custom_messages(**message_data)
        logging.debug("create_custom_messages response: %s", create_response)

        # Assuming the API returns an ID for the created message
        list_response = self.client.sys.list_custom_messages()
        self.assertIn("data", list_response)
        self.assertIn("keys", list_response["data"])
        self.assertGreater(len(list_response["data"]["keys"]), 0)

        self.custom_message_id = list_response["data"]["keys"][0]

        read_response = self.client.sys.read_custom_messages(id=self.custom_message_id)
        logging.debug("read_custom_messages response: %s", read_response)

        self.assertEqual(message_data["title"], read_response["data"]["title"])
        self.assertEqual(message_data["message"], read_response["data"]["message"])
        self.assertEqual(
            message_data["start_time"], read_response["data"]["start_time"]
        )
        self.assertEqual(message_data["end_time"], read_response["data"]["end_time"])

    @skipIf(
        not utils.vault_version_ge("1.16.0") or not utils.is_enterprise(),
        "Custom messages only supported in Enterprise Vault version 1.16.0 or greater",
    )
    def test_list_custom_messages(self):
        self.test_create_custom_message()

        list_response = self.client.sys.list_custom_messages()
        logging.debug("list_custom_messages response: %s", list_response)

        self.assertIn("data", list_response)
        self.assertIn("keys", list_response["data"])
        self.assertIn(self.custom_message_id, list_response["data"]["keys"])

    @skipIf(
        not utils.vault_version_ge("1.16.0") or not utils.is_enterprise(),
        "Custom messages only supported in Enterprise Vault version 1.16.0 or greater",
    )
    def test_read_custom_message(self):
        self.test_create_custom_message()

        read_response = self.client.sys.read_custom_messages(id=self.custom_message_id)
        logging.debug("read_custom_messages response: %s", read_response)

        self.assertIn("data", read_response)
        self.assertEqual("Test Message", read_response["data"]["title"])

    @skipIf(
        not utils.vault_version_ge("1.16.0") or not utils.is_enterprise(),
        "Custom messages only supported in Enterprise Vault version 1.16.0 or greater",
    )
    def test_update_custom_message(self):
        self.test_create_custom_message()

        current_time = datetime.utcnow()
        start_time_str = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = current_time + timedelta(minutes=5)
        end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        updated_message_data = {
            "id": self.custom_message_id,
            "title": "Updated Test Message",
            "message": "This is an updated test custom message.",
            "start_time": start_time_str,
            "end_time": end_time_str,
        }

        update_response = self.client.sys.update_custom_messages(**updated_message_data)
        logging.debug("update_custom_messages response: %s", update_response)

        read_response = self.client.sys.read_custom_messages(id=self.custom_message_id)
        logging.debug("read_custom_messages response after update: %s", read_response)

        self.assertEqual(updated_message_data["title"], read_response["data"]["title"])
        self.assertEqual(
            updated_message_data["message"], read_response["data"]["message"]
        )
        self.assertEqual(
            updated_message_data["start_time"], read_response["data"]["start_time"]
        )
        self.assertEqual(
            updated_message_data["end_time"], read_response["data"]["end_time"]
        )

    @skipIf(
        not utils.vault_version_ge("1.16.0") or not utils.is_enterprise(),
        "Custom messages only supported in Enterprise Vault version 1.16.0 or greater",
    )
    def test_delete_custom_message(self):
        self.test_create_custom_message()

        delete_response = self.client.sys.delete_custom_messages(
            id=self.custom_message_id
        )
        logging.debug("delete_custom_messages response: %s", delete_response)

        with self.assertRaises(exceptions.InvalidPath):
            self.client.sys.read_custom_messages(id=self.custom_message_id)

        self.custom_message_id = None

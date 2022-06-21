import json
import logging
from unittest import TestCase, skipIf

from parameterized import parameterized, param

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(
    utils.vault_version_lt("0.9.0"),
    "Policy class uses new parameters added >= Vault 0.9.0",
)
class TestPolicy(HvacIntegrationTestCase, TestCase):
    TEST_POLICY_NAME = "test-policy-policy"

    def tearDown(self):
        self.client.sys.delete_policy(
            name=self.TEST_POLICY_NAME,
        )
        super().tearDown()

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "pretty print false",
                pretty_print=False,
            ),
        ]
    )
    @skipIf(
        utils.vault_version_eq("0.11.0"),
        "Policy parsing broken in Vault version 0.11.0",
    )
    def test_create_or_update_policy(self, label, pretty_print=True):
        test_policy = {
            "path": {
                "test-path": {
                    "capabilities": ["read"],
                },
            },
        }
        create_policy_response = self.client.sys.create_or_update_policy(
            name=self.TEST_POLICY_NAME,
            policy=test_policy,
            pretty_print=pretty_print,
        )
        logging.debug("create_policy_response: %s" % create_policy_response)
        self.assertEqual(
            first=bool(create_policy_response),
            second=True,
        )

        read_policy_response = self.client.sys.read_policy(
            name=self.TEST_POLICY_NAME,
        )
        logging.debug("read_policy_response: %s" % read_policy_response)
        self.assertDictEqual(
            d1=json.loads(read_policy_response["data"]["rules"]),
            d2=test_policy,
        )

    def test_policy_manipulation(self):
        self.assertIn(
            member="root",
            container=self.client.sys.list_policies()["data"]["policies"],
        )
        self.assertIsNone(self.client.get_policy("test"))
        policy, parsed_policy = self.prep_policy("test")
        self.assertIn(
            member="test",
            container=self.client.sys.list_policies()["data"]["policies"],
        )
        self.assertEqual(policy, self.client.sys.read_policy("test")["data"]["rules"])
        self.assertEqual(parsed_policy, self.client.get_policy("test", parse=True))

        self.client.sys.delete_policy(
            name="test",
        )
        self.assertNotIn(
            member="test",
            container=self.client.sys.list_policies()["data"]["policies"],
        )

    def test_json_policy_manipulation(self):
        self.assertIn(
            member="root",
            container=self.client.sys.list_policies()["data"]["policies"],
        )

        policy = """
            path "sys" {
                policy = "deny"
            }
            path "secret" {
                policy = "write"
            }
        """
        self.client.sys.create_or_update_policy(
            name="test",
            policy=policy,
        )
        self.assertIn(
            member="test",
            container=self.client.sys.list_policies()["data"]["policies"],
        )

        self.client.sys.delete_policy("test")
        self.assertNotIn(
            member="test",
            container=self.client.sys.list_policies()["data"]["policies"],
        )

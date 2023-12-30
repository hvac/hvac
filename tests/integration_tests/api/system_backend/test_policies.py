import json
import logging
from unittest import TestCase, skipIf

from parameterized import parameterized, param
from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestPolicies(HvacIntegrationTestCase, TestCase):
    def setUp(self):
        super().setUp()
        self.client.sys.enable_secrets_engine(backend_type="kv", path="test")

    def tearDown(self):
        self.client.sys.disable_secrets_engine(path="test")
        super().tearDown()

    def test_create_acl_policy(self):
        policy_dict = {
            "name": "test-acl-policy",
            "policy": 'path "sys/health" { capabilities = ["read", "sudo"]}',
        }

        # Create policy
        create_or_update_policy_response = self.client.sys.create_or_update_acl_policy(
            name=policy_dict["name"], policy=policy_dict["policy"]
        )
        logging.debug(
            "create_or_update_policy_response: %s" % create_or_update_policy_response
        )

        self.assertEqual(
            first=policy_dict,
            second=self.client.sys.read_acl_policy(policy_dict["name"])["data"],
        )

    @parameterized.expand(
        [
            param(
                "pretty",
                pretty_print=True,
            ),
            param(
                "compact",
                pretty_print=False,
            ),
        ]
    )
    def test_create_acl_policy_dict(self, label, pretty_print):
        dict_policy = {
            "path": {
                "sys/health": {
                    "capabilities": ["read", "sudo"],
                },
            },
        }
        policy_dict = {
            "name": "test-acl-policy-dict",
            "policy": dict_policy,
        }

        # Create policy
        create_or_update_policy_response = self.client.sys.create_or_update_acl_policy(
            name=policy_dict["name"], policy=dict_policy, pretty_print=pretty_print
        )
        logging.debug(
            "create_or_update_policy_response: %s" % create_or_update_policy_response
        )

        policy_read_response = self.client.sys.read_acl_policy(policy_dict["name"])
        json_line_count = len(policy_read_response["data"]["policy"].splitlines())

        self.assertEqual(
            first=policy_dict["name"],
            second=policy_read_response["data"]["name"],
        )

        self.assertDictEqual(
            d1=json.loads(policy_read_response["data"]["policy"]),
            d2=policy_dict["policy"],
        )

        if pretty_print:
            self.assertGreater(
                a=json_line_count,
                b=1,
            )
        else:
            self.assertEqual(
                first=json_line_count,
                second=1,
            )

    def test_update_acl_policy(self):
        policy_dict = {
            "name": "test-acl-policy",
            "policy": 'path "sys/health" { capabilities = ["read", "sudo"]}',
        }

        # Create policy
        self.client.sys.create_or_update_acl_policy(
            name=policy_dict["name"],
            policy='path "sys/health" { capabilities = ["read"]}',
        )

        # Update policy
        self.client.sys.create_or_update_acl_policy(
            name=policy_dict["name"], policy=policy_dict["policy"]
        )

        self.assertEqual(
            first=policy_dict,
            second=self.client.sys.read_acl_policy(policy_dict["name"])["data"],
        )

    def test_read_acl_policy(self):
        policy_dict = {
            "name": "test-acl-policy",
            "policy": 'path "sys/health" { capabilities = ["read", "sudo"]}',
        }

        self.client.sys.create_or_update_acl_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
        )

        # Read the policy that was just created
        read_acl_policy_response = self.client.sys.read_acl_policy(
            name=policy_dict["name"],
        )
        logging.debug("read_acl_policy_response: %s" % read_acl_policy_response)

        self.assertEqual(
            first=policy_dict,
            second=read_acl_policy_response["data"],
        )

    def test_list_acl_policy(self):
        policy_dict = {
            "name": "test-acl-policy",
            "policy": 'path "sys/health" { capabilities = ["read", "sudo"]}',
        }

        self.client.sys.create_or_update_acl_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
        )

        list_acl_policies_response = self.client.sys.list_acl_policies()
        logging.debug("list_acl_policies_response: %s" % list_acl_policies_response)

        self.assertIn(
            member=policy_dict["name"],
            container=list_acl_policies_response["data"]["keys"],
        )

    def test_delete_acl_policy(self):
        policy_dict = {
            "name": "test-acl-policy",
            "policy": 'path "sys/health" { capabilities = ["read", "sudo"]}',
        }

        self.client.sys.create_or_update_acl_policy(
            name=policy_dict["name"], policy=policy_dict["policy"]
        )

        # Delete the policy that was just created
        delete_acl_policy_response = self.client.sys.delete_acl_policy(
            name=policy_dict["name"],
        )

        logging.debug("delete_acl_policy_response: %s" % delete_acl_policy_response)

        with self.assertRaises(exceptions.InvalidPath):
            self.client.sys.read_acl_policy(
                name=policy_dict["name"],
            )

    @skipIf(
        not utils.is_enterprise(), "RGP policies only supported with Enterprise Vault"
    )
    def test_create_rgp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-rgp-policy",
            "policy": policy,
        }

        # Create policy
        create_or_update_policy_response = self.client.sys.create_or_update_rgp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
        )
        logging.debug(
            "create_or_update_policy_response: %s" % create_or_update_policy_response
        )

        self.assertEqual(
            first=policy_dict,
            second=self.client.sys.read_rgp_policy(policy_dict["name"])["data"],
        )

    @skipIf(
        not utils.is_enterprise(), "RGP policies only supported with Enterprise Vault"
    )
    def test_update_rgp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-rgp-policy",
            "policy": policy,
        }

        # Create policy
        self.client.sys.create_or_update_rgp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level="hard-mandatory",
        )

        # Update policy
        self.client.sys.create_or_update_rgp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
        )

        self.assertEqual(
            first=policy_dict,
            second=self.client.sys.read_rgp_policy(policy_dict["name"])["data"],
        )

    @skipIf(
        not utils.is_enterprise(), "RGP policies only supported with Enterprise Vault"
    )
    def test_read_rgp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-rgp-policy",
            "policy": policy,
        }

        self.client.sys.create_or_update_rgp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
        )

        # Read the policy that was just created
        read_rgp_policy_response = self.client.sys.read_rgp_policy(
            name=policy_dict["name"],
        )
        logging.debug("read_rgp_policy_response: %s" % read_rgp_policy_response)

        self.assertEqual(
            first=policy_dict,
            second=read_rgp_policy_response["data"],
        )

    @skipIf(
        not utils.is_enterprise(), "RGP policies only supported with Enterprise Vault"
    )
    def test_list_rgp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-rgp-policy",
            "policy": policy,
        }

        self.client.sys.create_or_update_rgp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
        )

        list_rgp_policies_response = self.client.sys.list_rgp_policies()
        logging.debug("list_rgp_policies_response: %s" % list_rgp_policies_response)

        self.assertIn(
            member=policy_dict["name"],
            container=list_rgp_policies_response["data"]["keys"],
        )

    @skipIf(
        not utils.is_enterprise(), "RGP policies only supported with Enterprise Vault"
    )
    def test_delete_rgp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-rgp-policy",
            "policy": policy,
        }

        self.client.sys.create_or_update_rgp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
        )

        # Delete the policy that was just created
        delete_rgp_policy_response = self.client.sys.delete_rgp_policy(
            name=policy_dict["name"],
        )

        logging.debug("delete_rgp_policy_response: %s" % delete_rgp_policy_response)

        with self.assertRaises(exceptions.InvalidPath):
            self.client.sys.read_rgp_policy(
                name=policy_dict["name"],
            )

    @skipIf(
        not utils.is_enterprise(), "EGP policies only supported with Enterprise Vault"
    )
    def test_create_egp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-egp-policy",
            "policy": policy,
            "paths": ["/test"],
        }

        # Create policy
        create_or_update_policy_response = self.client.sys.create_or_update_egp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
            paths=policy_dict["paths"],
        )
        logging.debug(
            "create_or_update_policy_response: %s" % create_or_update_policy_response
        )

        self.assertEqual(
            first=policy_dict,
            second=self.client.sys.read_egp_policy(policy_dict["name"])["data"],
        )

    @skipIf(
        not utils.is_enterprise(), "EGP policies only supported with Enterprise Vault"
    )
    def test_update_egp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-egp-policy",
            "policy": policy,
            "paths": ["/test"],
        }

        # Create policy
        self.client.sys.create_or_update_egp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level="hard-mandatory",
            paths=policy_dict["paths"],
        )

        # Update policy
        self.client.sys.create_or_update_egp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
            paths=policy_dict["paths"],
        )

        self.assertEqual(
            first=policy_dict,
            second=self.client.sys.read_egp_policy(policy_dict["name"])["data"],
        )

    @skipIf(
        not utils.is_enterprise(), "EGP policies only supported with Enterprise Vault"
    )
    def test_read_egp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-egp-policy",
            "policy": policy,
            "paths": ["/test"],
        }

        self.client.sys.create_or_update_egp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
            paths=policy_dict["paths"],
        )

        # Read the policy that was just created
        read_egp_policy_response = self.client.sys.read_egp_policy(
            name=policy_dict["name"],
        )
        logging.debug("read_egp_policy_response: %s" % read_egp_policy_response)

        self.assertEqual(
            first=policy_dict,
            second=read_egp_policy_response["data"],
        )

    @skipIf(
        not utils.is_enterprise(), "EGP policies only supported with Enterprise Vault"
    )
    def test_list_egp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-egp-policy",
            "policy": policy,
            "paths": ["/test"],
        }

        self.client.sys.create_or_update_egp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
            paths=policy_dict["paths"],
        )

        list_egp_policies_response = self.client.sys.list_egp_policies()
        logging.debug("list_egp_policies_response: %s" % list_egp_policies_response)

        self.assertIn(
            member=policy_dict["name"],
            container=list_egp_policies_response["data"]["keys"],
        )

    @skipIf(
        not utils.is_enterprise(), "EGP policies only supported with Enterprise Vault"
    )
    def test_delete_egp_policy(self):
        policy = """import "time"
        import "strings"

        main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
            time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
        }
        """
        policy_dict = {
            "enforcement_level": "soft-mandatory",
            "name": "test-egp-policy",
            "policy": policy,
            "paths": ["/test"],
        }

        self.client.sys.create_or_update_egp_policy(
            name=policy_dict["name"],
            policy=policy_dict["policy"],
            enforcement_level=policy_dict["enforcement_level"],
            paths=policy_dict["paths"],
        )

        # Delete the policy that was just created
        delete_egp_policy_response = self.client.sys.delete_egp_policy(
            name=policy_dict["name"],
        )

        logging.debug("delete_egp_policy_response: %s" % delete_egp_policy_response)

        with self.assertRaises(exceptions.InvalidPath):
            self.client.sys.read_egp_policy(
                name=policy_dict["name"],
            )

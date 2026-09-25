import logging
from unittest import TestCase, skipIf

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(
    not utils.is_enterprise(), "Control Groups only supported with Enterprise Vault"
)
class TestControlGroup(HvacIntegrationTestCase, TestCase):
    TEST_KV_MOUNT_POINT = "control-group-kv"
    TEST_SECRET_PATH = "foo"
    TEST_SECRET = {"bar": "baz"}
    TEST_USERPASS_MOUNT_POINT = "control-group-userpass"
    TEST_APPROVER_GROUP_NAME = "control-group-approvers"
    TEST_REQUESTER_POLICY_NAME = "control-group-requester"
    TEST_APPROVER_POLICY_NAME = "control-group-approver"
    TEST_REQUESTER_USERNAME = "requester"
    TEST_APPROVER_USERNAME = "approver"
    TEST_PASSWORD = "hvac-test-password"

    def setUp(self):
        super().setUp()
        self.client.sys.enable_secrets_engine(
            backend_type="kv",
            path=self.TEST_KV_MOUNT_POINT,
            options={"version": "1"},
        )
        self.client.secrets.kv.v1.create_or_update_secret(
            path=self.TEST_SECRET_PATH,
            secret=self.TEST_SECRET,
            mount_point=self.TEST_KV_MOUNT_POINT,
        )

        requester_policy = """
        path "{mount_point}/*" {{
            capabilities = ["read"]
            control_group = {{
                factor "approvers" {{
                    identity {{
                        group_names = ["{group_name}"]
                        approvals = 1
                    }}
                }}
            }}
        }}
        """.format(
            mount_point=self.TEST_KV_MOUNT_POINT,
            group_name=self.TEST_APPROVER_GROUP_NAME,
        )
        self.client.sys.create_or_update_policy(
            name=self.TEST_REQUESTER_POLICY_NAME,
            policy=requester_policy,
        )
        approver_policy = """
        path "sys/control-group/authorize" {
            capabilities = ["create", "update"]
        }
        path "sys/control-group/request" {
            capabilities = ["create", "update"]
        }
        """
        self.client.sys.create_or_update_policy(
            name=self.TEST_APPROVER_POLICY_NAME,
            policy=approver_policy,
        )

        # Control groups are evaluated against identity entities, so both the
        # requester and approver log in via userpass to get an entity attached.
        self.client.sys.enable_auth_method(
            method_type="userpass",
            path=self.TEST_USERPASS_MOUNT_POINT,
        )
        self.client.auth.userpass.create_or_update_user(
            username=self.TEST_REQUESTER_USERNAME,
            password=self.TEST_PASSWORD,
            policies=[self.TEST_REQUESTER_POLICY_NAME],
            mount_point=self.TEST_USERPASS_MOUNT_POINT,
        )
        self.client.auth.userpass.create_or_update_user(
            username=self.TEST_APPROVER_USERNAME,
            password=self.TEST_PASSWORD,
            policies=[self.TEST_APPROVER_POLICY_NAME],
            mount_point=self.TEST_USERPASS_MOUNT_POINT,
        )
        self.requester_token = self._login(self.TEST_REQUESTER_USERNAME)
        self.approver_token = self._login(self.TEST_APPROVER_USERNAME)

        self.requester_entity_id = self._lookup_entity_id(self.requester_token)
        approver_entity_id = self._lookup_entity_id(self.approver_token)

        create_group_response = self.client.secrets.identity.create_or_update_group(
            name=self.TEST_APPROVER_GROUP_NAME,
            member_entity_ids=[approver_entity_id],
        )
        self.approver_group_id = create_group_response["data"]["id"]

    def tearDown(self):
        self.client.token = self.manager.root_token
        self.client.secrets.identity.delete_group(group_id=self.approver_group_id)
        self.client.sys.disable_auth_method(path=self.TEST_USERPASS_MOUNT_POINT)
        self.client.sys.delete_policy(name=self.TEST_REQUESTER_POLICY_NAME)
        self.client.sys.delete_policy(name=self.TEST_APPROVER_POLICY_NAME)
        self.client.sys.disable_secrets_engine(path=self.TEST_KV_MOUNT_POINT)
        super().tearDown()

    def _login(self, username):
        login_response = self.client.auth.userpass.login(
            username=username,
            password=self.TEST_PASSWORD,
            use_token=False,
            mount_point=self.TEST_USERPASS_MOUNT_POINT,
        )
        return login_response["auth"]["client_token"]

    def _lookup_entity_id(self, token):
        self.client.token = token
        entity_id = self.client.auth.token.lookup_self()["data"]["entity_id"]
        self.client.token = self.manager.root_token
        return entity_id

    def _create_control_group_request(self):
        """Read the control-group-protected secret as the requester, returning the resulting wrap_info."""
        self.client.token = self.requester_token
        read_response = self.client.secrets.kv.v1.read_secret(
            path=self.TEST_SECRET_PATH,
            mount_point=self.TEST_KV_MOUNT_POINT,
        )
        self.client.token = self.manager.root_token
        logging.debug("read_response: %s" % read_response)
        return read_response["wrap_info"]

    def test_check_control_group_request(self):
        wrap_info = self._create_control_group_request()

        check_response = self.client.sys.check_control_group_request(
            accessor=wrap_info["accessor"],
        )
        logging.debug("check_response: %s" % check_response)
        self.assertFalse(check_response["data"]["approved"])
        self.assertEqual(
            first="{mount_point}/{path}".format(
                mount_point=self.TEST_KV_MOUNT_POINT,
                path=self.TEST_SECRET_PATH,
            ),
            second=check_response["data"]["request_path"],
        )
        self.assertEqual(
            first=self.requester_entity_id,
            second=check_response["data"]["request_entity"]["id"],
        )
        self.assertFalse(check_response["data"]["authorizations"])

    def test_authorize_control_group(self):
        wrap_info = self._create_control_group_request()

        self.client.token = self.approver_token
        authorize_response = self.client.sys.authorize_control_group(
            accessor=wrap_info["accessor"],
        )
        logging.debug("authorize_response: %s" % authorize_response)
        self.assertTrue(authorize_response["data"]["approved"])

        check_response = self.client.sys.check_control_group_request(
            accessor=wrap_info["accessor"],
        )
        logging.debug("check_response: %s" % check_response)
        self.assertTrue(check_response["data"]["approved"])
        self.assertEqual(
            first=1,
            second=len(check_response["data"]["authorizations"]),
        )

        # Once approved, the requester can unwrap the token to get the secret.
        self.client.token = self.requester_token
        unwrap_response = self.client.sys.unwrap(token=wrap_info["token"])
        logging.debug("unwrap_response: %s" % unwrap_response)
        self.assertEqual(
            first=self.TEST_SECRET,
            second=unwrap_response["data"],
        )

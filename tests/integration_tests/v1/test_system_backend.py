import logging
from unittest import TestCase

from parameterized import parameterized, param

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestSystemBackend(HvacIntegrationTestCase, TestCase):
    TEST_KVV1_MOUNT_POINT = "kvv1_mount"

    def setUp(self):
        super().setUp()
        if (
            "%s/" % self.TEST_KVV1_MOUNT_POINT
            not in self.client.sys.list_mounted_secrets_engines()["data"]
        ):
            self.client.sys.enable_secrets_engine(
                backend_type="kv",
                path=self.TEST_KVV1_MOUNT_POINT,
                options=dict(version=1),
            )

    def tearDown(self):
        self.client.token = self.manager.root_token
        self.client.sys.disable_secrets_engine(path=self.TEST_KVV1_MOUNT_POINT)
        super().tearDown()

    def test_unseal_multi(self):
        cls = type(self)

        self.client.sys.seal()

        keys = cls.manager.keys

        result = self.client.sys.submit_unseal_keys(keys[0:2])

        self.assertTrue(result["sealed"])
        self.assertEqual(result["progress"], 2)

        result = self.client.sys.submit_unseal_key(reset=True)
        self.assertEqual(result["progress"], 0)
        result = self.client.sys.submit_unseal_keys(keys[1:3])
        self.assertTrue(result["sealed"])
        self.assertEqual(result["progress"], 2)
        self.client.sys.submit_unseal_keys(keys[0:1])
        result = self.client.sys.submit_unseal_keys(keys[2:3])
        self.assertFalse(result["sealed"])

    def test_seal_unseal(self):
        cls = type(self)

        self.assertFalse(self.client.sys.is_sealed())

        self.client.sys.seal()

        self.assertTrue(self.client.sys.is_sealed())

        cls.manager.unseal()

        self.assertFalse(self.client.sys.is_sealed())

    def test_ha_status(self):
        self.assertIn("ha_enabled", self.client.ha_status)

    def test_wrap_write(self):
        if "approle/" not in self.client.sys.list_auth_methods():
            self.client.sys.enable_auth_method("approle")

        self.client.write("auth/approle/role/testrole")
        result = self.client.write_data(
            "auth/approle/role/testrole/secret-id", wrap_ttl="10s"
        )
        self.assertIn("token", result["wrap_info"])
        self.client.sys.unwrap(result["wrap_info"]["token"])
        self.client.sys.disable_auth_method("approle")

    def test_auth_backend_manipulation(self):
        self.assertNotIn("github/", self.client.sys.list_auth_methods()["data"])

        self.client.sys.enable_auth_method("github")
        self.assertIn("github/", self.client.sys.list_auth_methods()["data"])

        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method("github")
        self.assertNotIn("github/", self.client.sys.list_auth_methods()["data"])

    def test_secret_backend_manipulation(self):
        self.assertNotIn(
            "test/", self.client.sys.list_mounted_secrets_engines()["data"]
        )

        self.client.sys.enable_secrets_engine("kv", path="test")
        self.assertIn("test/", self.client.sys.list_mounted_secrets_engines()["data"])

        secret_backend_tuning = self.client.sys.read_mount_configuration(path="test")
        self.assertEqual(secret_backend_tuning["data"]["max_lease_ttl"], 2764800)
        self.assertEqual(secret_backend_tuning["data"]["default_lease_ttl"], 2764800)

        self.client.sys.tune_mount_configuration(
            path="test",
            default_lease_ttl="3600s",
            max_lease_ttl="8600s",
        )
        secret_backend_tuning = self.client.sys.read_mount_configuration(path="test")

        self.assertIn("max_lease_ttl", secret_backend_tuning["data"])
        self.assertEqual(secret_backend_tuning["data"]["max_lease_ttl"], 8600)
        self.assertIn("default_lease_ttl", secret_backend_tuning["data"])
        self.assertEqual(secret_backend_tuning["data"]["default_lease_ttl"], 3600)

        self.client.sys.move_backend("test", "foobar")
        self.assertNotIn(
            "test/", self.client.sys.list_mounted_secrets_engines()["data"]
        )
        self.assertIn("foobar/", self.client.sys.list_mounted_secrets_engines()["data"])

        self.client.token = self.manager.root_token
        self.client.sys.disable_secrets_engine("foobar")
        self.assertNotIn(
            "foobar/", self.client.sys.list_mounted_secrets_engines()["data"]
        )

    def test_audit_backend_manipulation(self):
        self.assertNotIn("tmpfile/", self.client.sys.list_enabled_audit_devices())

        options = {"path": "/tmp/vault.audit.log"}

        self.client.sys.enable_audit_device("file", options=options, path="tmpfile")
        self.assertIn("tmpfile/", self.client.sys.list_enabled_audit_devices()["data"])

        self.client.token = self.manager.root_token
        self.client.sys.disable_audit_device("tmpfile")
        self.assertNotIn(
            "tmpfile/", self.client.sys.list_enabled_audit_devices()["data"]
        )

    def test_policy_manipulation(self):
        self.assertIn("root", self.client.sys.list_policies()["keys"])
        with self.assertRaises(exceptions.InvalidPath):
            self.client.sys.read_policy("test")

        policy, parsed_policy = self.prep_policy("test")
        self.assertIn("test", self.client.sys.list_policies()["keys"])
        test_policy_read_resp = self.client.sys.read_policy("test")
        logging.debug("test_policy_read_resp: %s" % test_policy_read_resp)
        self.assertEqual(policy, test_policy_read_resp["rules"])
        self.assertEqual(parsed_policy, self.client.get_policy("test", parse=True))

        self.client.sys.delete_policy("test")
        self.assertNotIn("test", self.client.sys.list_policies()["keys"])

    def test_json_policy_manipulation(self):
        self.assertIn("root", self.client.sys.list_policies()["keys"])

        policy = """
            path "sys" {
                policy = "deny"
            }
            path "secret" {
                policy = "write"
            }
        """
        self.client.sys.create_or_update_policy("test", policy)
        self.assertIn("test", self.client.sys.list_policies()["keys"])

        self.client.sys.delete_policy("test")
        self.assertNotIn("test", self.client.sys.list_policies()["keys"])

    def test_cubbyhole_auth(self):
        orig_token = self.client.token

        resp = self.client.auth.token.create(ttl="6h", wrap_ttl="1h")
        self.assertEqual(resp["wrap_info"]["ttl"], 3600)

        wrapped_token = resp["wrap_info"]["token"]
        self.client.auth_cubbyhole(wrapped_token)
        self.assertNotEqual(self.client.token, orig_token)
        self.assertNotEqual(self.client.token, wrapped_token)
        self.assertTrue(self.client.is_authenticated())

        self.client.token = orig_token
        self.assertTrue(self.client.is_authenticated())

    def test_rekey_multi(self):
        cls = type(self)

        self.assertFalse(self.client.rekey_status["started"])

        self.client.sys.start_rekey()
        self.assertTrue(self.client.rekey_status["started"])

        self.client.sys.cancel_rekey()
        self.assertFalse(self.client.rekey_status["started"])

        result = self.client.sys.start_rekey()

        keys = cls.manager.keys

        result = self.client.sys.rekey_multi(keys, nonce=result["nonce"])
        self.assertTrue(result["complete"])

        cls.manager.keys = result["keys"]
        cls.manager.unseal()

    def test_rotate(self):
        status = self.client.key_status

        self.client.sys.rotate_encryption_key()

        self.assertGreater(self.client.key_status["term"], status["term"])

    def test_wrapped_token_success(self):
        wrap = self.client.auth.token.create(wrap_ttl="1m")

        # Unwrap token
        result = self.client.sys.unwrap(wrap["wrap_info"]["token"])
        self.assertTrue(result["auth"]["client_token"])

        # Validate token
        lookup = self.client.auth.token.lookup(result["auth"]["client_token"])
        self.assertEqual(result["auth"]["client_token"], lookup["data"]["id"])

    def test_wrapped_token_intercept(self):
        wrap = self.client.auth.token.create(wrap_ttl="1m")

        # Intercept wrapped token
        self.client.sys.unwrap(wrap["wrap_info"]["token"])

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.InvalidRequest):
            self.client.sys.unwrap(wrap["wrap_info"]["token"])

    def test_wrapped_token_cleanup(self):
        wrap = self.client.auth.token.create(wrap_ttl="1m")

        _token = self.client.token
        self.client.sys.unwrap(wrap["wrap_info"]["token"])
        self.assertEqual(self.client.token, _token)

    def test_wrapped_token_revoke(self):
        wrap = self.client.auth.token.create(wrap_ttl="1m")

        # Revoke token before it's unwrapped
        self.client.auth.token.revoke_accessor(wrap["wrap_info"]["wrapped_accessor"])

        # Unwrap token anyway
        result = self.client.sys.unwrap(wrap["wrap_info"]["token"])
        self.assertTrue(result["auth"]["client_token"])

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            self.client.auth.token.lookup(result["auth"]["client_token"])

    def test_wrapped_client_token_success(self):
        wrap = self.client.auth.token.create(wrap_ttl="1m")
        self.client.token = wrap["wrap_info"]["token"]

        # Unwrap token
        result = self.client.sys.unwrap()
        self.assertTrue(result["auth"]["client_token"])

        # Validate token
        self.client.token = result["auth"]["client_token"]
        lookup = self.client.auth.token.lookup(result["auth"]["client_token"])
        self.assertEqual(result["auth"]["client_token"], lookup["data"]["id"])

    def test_wrapped_client_token_intercept(self):
        wrap = self.client.auth.token.create(wrap_ttl="1m")
        self.client.token = wrap["wrap_info"]["token"]

        # Intercept wrapped token
        self.client.sys.unwrap()

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.InvalidRequest):
            self.client.sys.unwrap()

    def test_wrapped_client_token_cleanup(self):
        wrap = self.client.auth.token.create(wrap_ttl="1m")

        _token = self.client.token
        self.client.token = wrap["wrap_info"]["token"]
        self.client.sys.unwrap()

        self.assertNotEqual(self.client.token, wrap)
        self.assertNotEqual(self.client.token, _token)

    def test_wrapped_client_token_revoke(self):
        wrap = self.client.auth.token.create(wrap_ttl="1m")

        # Revoke token before it's unwrapped
        self.client.auth.token.revoke_accessor(wrap["wrap_info"]["wrapped_accessor"])

        # Unwrap token anyway
        self.client.token = wrap["wrap_info"]["token"]
        result = self.client.sys.unwrap()
        self.assertTrue(result["auth"]["client_token"])

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            self.client.auth.token.lookup(result["auth"]["client_token"])

    def test_start_generate_root_with_completion(self):
        test_otp = utils.get_generate_root_otp()

        self.assertFalse(self.client.generate_root_status["started"])
        start_generate_root_response = self.client.sys.start_root_token_generation(
            otp=test_otp,
        )
        logging.debug("generate_root_response: %s" % start_generate_root_response)
        self.assertTrue(self.client.generate_root_status["started"])

        nonce = start_generate_root_response["nonce"]

        last_generate_root_response = {}
        for key in self.manager.keys[0:3]:
            last_generate_root_response = self.client.sys.generate_root(
                key=key,
                nonce=nonce,
            )
        logging.debug("last_generate_root_response: %s" % last_generate_root_response)
        self.assertFalse(self.client.generate_root_status["started"])

        new_root_token = utils.decode_generated_root_token(
            encoded_token=last_generate_root_response["encoded_root_token"],
            otp=test_otp,
        )
        logging.debug("new_root_token: %s" % new_root_token)
        token_lookup_resp = self.client.auth.token.lookup(token=new_root_token)
        logging.debug("token_lookup_resp: %s" % token_lookup_resp)

        # Assert our new root token is properly formed and authenticated
        self.client.token = new_root_token
        if self.client.is_authenticated():
            self.manager.root_token = new_root_token
        else:
            # If our new token was unable to authenticate, set the test client's token back to the original value
            self.client.token = self.manager.root_token
            self.fail("Unable to authenticate with the newly generated root token.")

    def test_start_generate_root_then_cancel(self):
        test_otp = utils.get_generate_root_otp()

        self.assertFalse(self.client.generate_root_status["started"])
        self.client.sys.start_root_token_generation(
            otp=test_otp,
        )
        self.assertTrue(self.client.generate_root_status["started"])

        self.client.sys.cancel_root_generation()
        self.assertFalse(self.client.generate_root_status["started"])

    def test_tune_auth_backend(self):
        test_mount_point = "tune-approle"
        test_description = "this is a test auth backend"
        test_max_lease_ttl = 12345678
        if f"{test_mount_point}/" in self.client.sys.list_auth_methods():
            self.client.sys.disable_auth_method(test_mount_point)
        self.client.sys.enable_auth_method(method_type="approle", path=test_mount_point)

        expected_status_code = 204
        response = self.client.sys.tune_auth_method(
            path=test_mount_point,
            description=test_description,
            max_lease_ttl=test_max_lease_ttl,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

        response = self.client.sys.read_auth_method_tuning(path=test_mount_point)

        self.assertEqual(
            first=test_max_lease_ttl, second=response["data"]["max_lease_ttl"]
        )

        self.client.sys.disable_auth_method(path=test_mount_point)

    def test_read_lease(self):
        # Set up a test pki backend and issue a cert against some role so we.
        utils.configure_pki(client=self.client)
        pki_issue_response = self.client.write_data(
            path="pki/issue/my-role",
            data=dict(common_name="test.hvac.com"),
        )

        # Read the lease of our test cert that was just issued.
        read_lease_response = self.client.sys.read_lease(pki_issue_response["lease_id"])

        # Validate we received the expected lease ID back in our response.
        self.assertEqual(
            first=pki_issue_response["lease_id"],
            second=read_lease_response["data"]["id"],
        )

        # Reset integration test state.
        utils.disable_pki(client=self.client)

    @parameterized.expand(
        [
            param(
                "hash returned",
            ),
            param(
                "audit backend not enabled",
                enable_first=False,
                raises=exceptions.InvalidRequest,
                exception_message="unknown audit backend",
            ),
        ]
    )
    def test_audit_hash(
        self,
        label,
        enable_first=True,
        test_input="hvac-rox",
        raises=None,
        exception_message="",
    ):
        audit_backend_path = "tmpfile"
        self.client.sys.disable_audit_device("tmpfile")
        if enable_first:
            options = {"path": "/tmp/vault.audit.log"}
            self.client.sys.enable_audit_device(
                "file", options=options, path=audit_backend_path
            )

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.sys.calculate_hash(
                    path=audit_backend_path, input_to_hash=test_input
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            audit_hash_response = self.client.sys.calculate_hash(
                path=audit_backend_path,
                input_to_hash=test_input,
            )
            logging.debug("audit_hash_response: %s" % audit_hash_response)
            self.assertIn(
                member="hmac-sha256:",
                container=audit_hash_response["data"]["hash"],
            )
        self.client.sys.disable_audit_device("tmpfile")

    def test_get_secret_backend_tuning(self):
        secret_backend_tuning = self.client.sys.read_mount_configuration(
            self.TEST_KVV1_MOUNT_POINT
        )
        self.assertIn(
            member="default_lease_ttl",
            container=secret_backend_tuning["data"],
        )

    def test_get_backed_up_keys(self):
        with self.assertRaises(exceptions.InvalidRequest) as cm:
            self.client.sys.read_backup_keys()
            self.assertEqual(
                first="no backed-up keys found",
                second=str(cm.exception),
            )

import logging
from unittest import TestCase, skipIf

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class IntegrationTest(HvacIntegrationTestCase, TestCase):
    def setUp(self):
        super().setUp()
        if "secret/" not in self.client.sys.list_mounted_secrets_engines()["data"]:
            self.client.sys.enable_secrets_engine(
                backend_type="kv",
                path="secret",
                options=dict(version=1),
            )

    def test_generic_secret_backend(self):
        self.client.write("secret/foo", zap="zip")
        result = self.client.read("secret/foo")

        assert result["data"]["zap"] == "zip"

        self.client.delete("secret/foo")

    def test_list_directory(self):
        self.client.write("secret/test-list/bar/foo", value="bar")
        self.client.write("secret/test-list/foo", value="bar")
        result = self.client.list("secret/test-list")

        assert result["data"]["keys"] == ["bar/", "foo"]

        self.client.delete("secret/test-list/bar/foo")
        self.client.delete("secret/test-list/foo")

    def test_write_with_response(self):
        if "transit/" in self.client.sys.list_mounted_secrets_engines()["data"]:
            self.client.sys.disable_secrets_engine("transit")
        self.client.sys.enable_secrets_engine("transit")

        plaintext = "test"

        self.client.write("transit/keys/foo")

        result = self.client.write("transit/encrypt/foo", plaintext=plaintext)
        ciphertext = result["data"]["ciphertext"]

        result = self.client.write("transit/decrypt/foo", ciphertext=ciphertext)
        assert result["data"]["plaintext"] == plaintext

    def test_read_nonexistent_key(self):
        assert not self.client.read("secret/I/dont/exist")

    def test_auth_token_manipulation(self):
        result = self.client.auth.token.create(ttl="1h", renewable=True)
        assert result["auth"]["client_token"]

        lookup = self.client.lookup_token(result["auth"]["client_token"])
        assert result["auth"]["client_token"] == lookup["data"]["id"]

        renew = self.client.renew_token(lookup["data"]["id"])
        assert result["auth"]["client_token"] == renew["auth"]["client_token"]

        self.client.revoke_token(lookup["data"]["id"])

        try:
            lookup = self.client.lookup_token(result["auth"]["client_token"])
            assert False
        except exceptions.Forbidden:
            assert True
        except exceptions.InvalidPath:
            assert True
        except exceptions.InvalidRequest:
            assert True

    def test_self_auth_token_manipulation(self):
        result = self.client.auth.token.create(ttl="1h", renewable=True)
        assert result["auth"]["client_token"]
        self.client.token = result["auth"]["client_token"]

        lookup = self.client.lookup_token(result["auth"]["client_token"])
        assert result["auth"]["client_token"] == lookup["data"]["id"]

        renew = self.client.auth.token.renew_self()
        assert result["auth"]["client_token"] == renew["auth"]["client_token"]

        self.client.revoke_token(lookup["data"]["id"])

        try:
            lookup = self.client.lookup_token(result["auth"]["client_token"])
            assert False
        except exceptions.Forbidden:
            assert True
        except exceptions.InvalidPath:
            assert True
        except exceptions.InvalidRequest:
            assert True

    def test_userpass_auth(self):
        if "userpass/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method("userpass")

        self.client.sys.enable_auth_method("userpass")

        self.client.write(
            "auth/userpass/users/testuser", password="testpass", policies="not_root"
        )

        result = self.client.auth.userpass.login("testuser", "testpass")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method("userpass")

    def test_create_userpass(self):
        if "userpass/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("userpass")

        self.client.auth.userpass.create_or_update_user(
            "testcreateuser", "testcreateuserpass", policies="not_root"
        )

        result = self.client.auth.userpass.login("testcreateuser", "testcreateuserpass")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        # Test ttl:
        self.client.token = self.manager.root_token
        self.client.auth.userpass.create_or_update_user(
            "testcreateuser", "testcreateuserpass", policies="not_root", ttl="10s"
        )
        self.client.token = result["auth"]["client_token"]

        result = self.client.auth.userpass.login("testcreateuser", "testcreateuserpass")

        assert result["auth"]["lease_duration"] == 10

        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method("userpass")

    def test_write_data(self):
        self.client.write_data("secret/foo", data={"path": "foo1", "foo": "foo2"})
        result = self.client.read("secret/foo")

        assert result["data"]["path"] == "foo1"
        assert result["data"]["foo"] == "foo2"

        self.client.delete("secret/foo")

    def test_missing_token(self):
        client = utils.create_client()
        assert not client.is_authenticated()

    def test_invalid_token(self):
        client = utils.create_client(token="not-a-real-token")
        assert not client.is_authenticated()

    def test_illegal_token(self):
        client = utils.create_client(token="token-with-new-line\n")
        try:
            client.is_authenticated()
        except ValueError as e:
            assert "Invalid header value" in str(e)

    def test_broken_token(self):
        client = utils.create_client(token="\x1b")
        try:
            client.is_authenticated()
        except exceptions.InvalidRequest as e:
            assert "invalid header value" in str(e)

    def test_client_authenticated(self):
        assert self.client.is_authenticated()

    def test_client_logout(self):
        self.client.logout()
        assert not self.client.is_authenticated()

    def test_client_logout_and_revoke(self):
        # create a new token
        result = self.client.auth.token.create(ttl="1h", renewable=True)
        # set the token
        self.client.token = result["auth"]["client_token"]

        # logout and revoke the token
        self.client.logout(revoke_token=True)
        # set the original token back
        self.client.token = result["auth"]["client_token"]
        # confirm that it no longer is able to authenticate
        assert not self.client.is_authenticated()

    def test_gh51(self):
        key = "secret/http://test.com"

        self.client.write(key, foo="bar")

        result = self.client.read(key)

        assert result["data"]["foo"] == "bar"

    def test_token_accessor(self):
        # Create token, check accessor is provided
        result = self.client.auth.token.create(ttl="1h")
        token_accessor = result["auth"].get("accessor", None)
        assert token_accessor

        # Look up token by accessor, make sure token is excluded from results
        lookup = self.client.lookup_token(token_accessor, accessor=True)
        assert lookup["data"]["accessor"] == token_accessor
        assert not lookup["data"]["id"]

        # Revoke token using the accessor
        self.client.revoke_token(token_accessor, accessor=True)

        # Look up by accessor should fail
        with self.assertRaises(exceptions.InvalidRequest):
            lookup = self.client.lookup_token(token_accessor, accessor=True)

        # As should regular lookup
        with self.assertRaises(exceptions.Forbidden):
            lookup = self.client.lookup_token(result["auth"]["client_token"])

    def test_create_token_explicit_max_ttl(self):
        token = self.client.auth.token.create(ttl="30m", explicit_max_ttl="5m")

        assert token["auth"]["client_token"]

        assert token["auth"]["lease_duration"] == 300

        # Validate token
        lookup = self.client.lookup_token(token["auth"]["client_token"])
        assert token["auth"]["client_token"] == lookup["data"]["id"]

    def test_create_token_max_ttl(self):
        token = self.client.auth.token.create(ttl="5m")

        assert token["auth"]["client_token"]

        assert token["auth"]["lease_duration"] == 300

        # Validate token
        lookup = self.client.lookup_token(token["auth"]["client_token"])
        assert token["auth"]["client_token"] == lookup["data"]["id"]

    def test_create_token_periodic(self):
        token = self.client.auth.token.create(period="30m")

        assert token["auth"]["client_token"]

        assert token["auth"]["lease_duration"] == 1800

        # Validate token
        lookup = self.client.lookup_token(token["auth"]["client_token"])
        assert token["auth"]["client_token"] == lookup["data"]["id"]
        assert lookup["data"]["period"] == 1800

    def test_token_roles(self):
        # Create token role
        assert (
            self.client.auth.token.create_or_update_role("testrole").status_code == 204
        )

        # List token roles
        during = self.client.auth.token.list_roles()["data"]["keys"]
        assert len(during) == 1
        assert during[0] == "testrole"

        # Delete token role
        self.client.auth.token.delete_role("testrole")

    def test_create_token_w_role(self):
        # Create policy
        self.prep_policy("testpolicy")

        # Create token role w/ policy
        assert (
            self.client.auth.token.create_or_update_role(
                "testrole", allowed_policies="testpolicy"
            ).status_code
            == 204
        )

        # Create token against role
        token = self.client.auth.token.create(ttl="1h", role_name="testrole")
        assert token["auth"]["client_token"]
        assert token["auth"]["policies"] == ["default", "testpolicy"]

        # Cleanup
        self.client.auth.token.delete_role("testrole")
        self.client.sys.delete_policy("testpolicy")

    def test_auth_gcp_alternate_mount_point_with_no_client_token_exception(self):
        test_mount_point = "gcp-custom-path"
        # Turn on the gcp backend with a custom mount_point path specified.
        if f"{test_mount_point}/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method(test_mount_point)
        self.client.sys.enable_auth_method("gcp", path=test_mount_point)

        # Drop the client's token to replicate a typical end user's use of any auth method.
        # I.e., its reasonable to expect the method is being called to _retrieve_ a token in the first place.
        self.client.token = None

        # Load a mock JWT stand in for a real document from GCP.
        with open(utils.get_config_file_path("example.jwt")) as fp:
            jwt = fp.read()

        # When attempting to auth (POST) to an auth backend mounted at a different path than the default, we expect a
        # generic 'missing client token' response from Vault.
        expected_exception = (
            exceptions.InvalidRequest
            if utils.vault_version_lt("1.10.0")
            else exceptions.Forbidden
        )
        with self.assertRaises(expected_exception) as assertRaisesContext:
            self.client.auth.gcp.login("example-role", jwt)

        expected_exception_message = (
            "missing client token"
            if utils.vault_version_lt("1.10.0")
            else "permission denied"
        )
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertIn(expected_exception_message, actual_exception_message)

        # Reset test state.
        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method(path=test_mount_point)

    @skipIf(
        utils.if_vault_version("0.10.0"),
        "KV version 2 secret engine not available before Vault version 0.10.0",
    )
    def test_kv2_secret_backend(self):
        if "test/" in self.client.sys.list_mounted_secrets_engines()["data"]:
            self.client.sys.disable_secrets_engine("test")
        self.client.sys.enable_secrets_engine(
            "kv", path="test", options={"version": "2"}
        )

        secret_backends = self.client.sys.list_mounted_secrets_engines()["data"]

        assert "test/" in secret_backends
        self.assertDictEqual(secret_backends["test/"]["options"], {"version": "2"})

        self.client.sys.disable_secrets_engine("test")

    def test_seal_status(self):
        seal_status_property = self.client.seal_status
        logging.debug("seal_status_property: %s" % seal_status_property)
        self.assertIn(
            member="sealed",
            container=seal_status_property,
        )

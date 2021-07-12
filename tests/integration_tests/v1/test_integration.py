import logging
from unittest import TestCase, skipIf

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class IntegrationTest(HvacIntegrationTestCase, TestCase):
    def setUp(self):
        super(IntegrationTest, self).setUp()
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

    def test_gh51(self):
        key = "secret/http://test.com"

        self.client.write(key, foo="bar")

        result = self.client.read(key)

        assert result["data"]["foo"] == "bar"

    def test_auth_gcp_alternate_mount_point_with_no_client_token_exception(self):
        test_mount_point = "gcp-custom-path"
        # Turn on the gcp backend with a custom mount_point path specified.
        if (
            "{0}/".format(test_mount_point)
            in self.client.sys.list_auth_methods()["data"]
        ):
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
        with self.assertRaises(exceptions.InvalidRequest) as assertRaisesContext:
            self.client.auth.gcp.login("example-role", jwt)

        expected_exception_message = "missing client token"
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

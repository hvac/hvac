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
        result = self.client.create_token(lease="1h", renewable=True)
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
        result = self.client.create_token(lease="1h", renewable=True)
        assert result["auth"]["client_token"]
        self.client.token = result["auth"]["client_token"]

        lookup = self.client.lookup_token(result["auth"]["client_token"])
        assert result["auth"]["client_token"] == lookup["data"]["id"]

        renew = self.client.renew_self_token()
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

        result = self.client.auth_userpass("testuser", "testpass")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method("userpass")

    def test_create_userpass(self):
        if "userpass/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("userpass")

        self.client.create_userpass(
            "testcreateuser", "testcreateuserpass", policies="not_root"
        )

        result = self.client.auth_userpass("testcreateuser", "testcreateuserpass")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        # Test ttl:
        self.client.token = self.manager.root_token
        self.client.create_userpass(
            "testcreateuser", "testcreateuserpass", policies="not_root", ttl="10s"
        )
        self.client.token = result["auth"]["client_token"]

        result = self.client.auth_userpass("testcreateuser", "testcreateuserpass")

        assert result["auth"]["lease_duration"] == 10

        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method("userpass")

    def test_list_userpass(self):
        if "userpass/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("userpass")

        # add some users and confirm that they show up in the list
        self.client.create_userpass(
            "testuserone", "testuseronepass", policies="not_root"
        )
        self.client.create_userpass(
            "testusertwo", "testusertwopass", policies="not_root"
        )

        user_list = self.client.list_userpass()
        assert "testuserone" in user_list["data"]["keys"]
        assert "testusertwo" in user_list["data"]["keys"]

        # delete all the users and confirm that list_userpass() doesn't fail
        for user in user_list["data"]["keys"]:
            self.client.delete_userpass(user)

        no_users_list = self.client.list_userpass()
        assert no_users_list is None

    def test_read_userpass(self):
        if "userpass/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("userpass")

        # create user to read
        self.client.create_userpass("readme", "mypassword", policies="not_root")

        # test that user can be read
        read_user = self.client.read_userpass("readme")
        assert "not_root" in read_user["data"]["policies"]

        # teardown
        self.client.sys.disable_auth_method("userpass")

    def test_update_userpass_policies(self):
        if "userpass/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("userpass")

        # create user and then update its policies
        self.client.create_userpass(
            "updatemypolicies", "mypassword", policies="not_root"
        )
        self.client.update_userpass_policies(
            "updatemypolicies", policies="somethingelse"
        )

        # test that policies have changed
        updated_user = self.client.read_userpass("updatemypolicies")
        assert "somethingelse" in updated_user["data"]["policies"]

        # teardown
        self.client.sys.disable_auth_method("userpass")

    def test_update_userpass_password(self):
        if "userpass/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("userpass")

        # create user and then change its password
        self.client.create_userpass("changeme", "mypassword", policies="not_root")
        self.client.update_userpass_password("changeme", "mynewpassword")

        # test that new password authenticates user
        result = self.client.auth_userpass("changeme", "mynewpassword")
        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        # teardown
        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method("userpass")

    def test_delete_userpass(self):
        if "userpass/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("userpass")

        self.client.create_userpass(
            "testcreateuser", "testcreateuserpass", policies="not_root"
        )

        result = self.client.auth_userpass("testcreateuser", "testcreateuserpass")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        self.client.token = self.manager.root_token
        self.client.delete_userpass("testcreateuser")
        self.assertRaises(
            exceptions.InvalidRequest,
            self.client.auth_userpass,
            "testcreateuser",
            "testcreateuserpass",
        )

    def test_app_id_auth(self):
        if "app-id/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method("app-id")

        self.client.sys.enable_auth_method("app-id")

        self.client.write("auth/app-id/map/app-id/foo", value="not_root")
        self.client.write("auth/app-id/map/user-id/bar", value="foo")

        result = self.client.auth_app_id("foo", "bar")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method("app-id")

    def test_create_app_id(self):
        if "app-id/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("app-id")

        self.client.create_app_id(
            "testappid", policies="not_root", display_name="displayname"
        )

        result = self.client.read("auth/app-id/map/app-id/testappid")
        lib_result = self.client.get_app_id("testappid")
        del result["request_id"]
        del lib_result["request_id"]
        assert result == lib_result

        assert result["data"]["key"] == "testappid"
        assert result["data"]["display_name"] == "displayname"
        assert result["data"]["value"] == "not_root"
        self.client.delete_app_id("testappid")
        assert self.client.get_app_id("testappid")["data"] is None

        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method("app-id")

    def test_create_user_id(self):
        if "app-id/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("app-id")

        self.client.create_app_id(
            "testappid", policies="not_root", display_name="displayname"
        )
        self.client.create_user_id("testuserid", app_id="testappid")

        result = self.client.read("auth/app-id/map/user-id/testuserid")
        lib_result = self.client.get_user_id("testuserid")
        del result["request_id"]
        del lib_result["request_id"]
        assert result == lib_result

        assert result["data"]["key"] == "testuserid"
        assert result["data"]["value"] == "testappid"

        result = self.client.auth_app_id("testappid", "testuserid")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()
        self.client.token = self.manager.root_token
        self.client.delete_user_id("testuserid")
        assert self.client.get_user_id("testuserid")["data"] is None

        self.client.token = self.manager.root_token
        self.client.sys.disable_auth_method("app-id")

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

    def test_revoke_self_token(self):
        if "userpass/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method("userpass")

        self.client.sys.enable_auth_method("userpass")

        self.client.write(
            "auth/userpass/users/testuser", password="testpass", policies="not_root"
        )

        self.client.auth_userpass("testuser", "testpass")

        self.client.revoke_self_token()
        assert not self.client.is_authenticated()

    def test_gh51(self):
        key = "secret/http://test.com"

        self.client.write(key, foo="bar")

        result = self.client.read(key)

        assert result["data"]["foo"] == "bar"

    def test_token_accessor(self):
        # Create token, check accessor is provided
        result = self.client.create_token(lease="1h")
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

        token = self.client.create_token(ttl="30m", explicit_max_ttl="5m")

        assert token["auth"]["client_token"]

        assert token["auth"]["lease_duration"] == 300

        # Validate token
        lookup = self.client.lookup_token(token["auth"]["client_token"])
        assert token["auth"]["client_token"] == lookup["data"]["id"]

    def test_create_token_max_ttl(self):

        token = self.client.create_token(ttl="5m")

        assert token["auth"]["client_token"]

        assert token["auth"]["lease_duration"] == 300

        # Validate token
        lookup = self.client.lookup_token(token["auth"]["client_token"])
        assert token["auth"]["client_token"] == lookup["data"]["id"]

    def test_create_token_periodic(self):

        token = self.client.create_token(period="30m")

        assert token["auth"]["client_token"]

        assert token["auth"]["lease_duration"] == 1800

        # Validate token
        lookup = self.client.lookup_token(token["auth"]["client_token"])
        assert token["auth"]["client_token"] == lookup["data"]["id"]
        assert lookup["data"]["period"] == 1800

    def test_token_roles(self):
        # No roles, list_token_roles == None
        before = self.client.list_token_roles()
        assert not before

        # Create token role
        assert self.client.create_token_role("testrole").status_code == 204

        # List token roles
        during = self.client.list_token_roles()["data"]["keys"]
        assert len(during) == 1
        assert during[0] == "testrole"

        # Delete token role
        self.client.delete_token_role("testrole")

        # No roles, list_token_roles == None
        after = self.client.list_token_roles()
        assert not after

    def test_create_token_w_role(self):
        # Create policy
        self.prep_policy("testpolicy")

        # Create token role w/ policy
        assert (
            self.client.create_token_role(
                "testrole", allowed_policies="testpolicy"
            ).status_code
            == 204
        )

        # Create token against role
        token = self.client.create_token(lease="1h", role="testrole")
        assert token["auth"]["client_token"]
        assert token["auth"]["policies"] == ["default", "testpolicy"]

        # Cleanup
        self.client.delete_token_role("testrole")
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

    def test_create_kubernetes_configuration(self):
        expected_status_code = 204
        test_mount_point = "k8s"

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if f"{test_mount_point}/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method(test_mount_point)
        self.client.sys.enable_auth_method("kubernetes", path=test_mount_point)

        with open(utils.get_config_file_path("client-cert.pem")) as fp:
            certificate = fp.read()
            response = self.client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

        # Reset integration test state
        self.client.sys.disable_auth_method(path=test_mount_point)

    def test_get_kubernetes_configuration(self):
        test_host = "127.0.0.1:80"
        test_mount_point = "k8s"

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if f"{test_mount_point}/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method(test_mount_point)
        self.client.sys.enable_auth_method("kubernetes", path=test_mount_point)
        with open(utils.get_config_file_path("client-cert.pem")) as fp:
            certificate = fp.read()
            self.client.create_kubernetes_configuration(
                kubernetes_host=test_host,
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        # Test that we can retrieve the configuration
        response = self.client.get_kubernetes_configuration(
            mount_point=test_mount_point
        )
        self.assertIn(
            member="data",
            container=response,
        )
        self.assertEqual(
            first=test_host, second=response["data"].get("kubernetes_host")
        )

        # Reset integration test state
        self.client.sys.disable_auth_method(path=test_mount_point)

    def test_create_kubernetes_role(self):
        test_role_name = "test_role"
        test_mount_point = "k8s"
        expected_status_code = 204

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if f"{test_mount_point}/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method(test_mount_point)
        self.client.sys.enable_auth_method("kubernetes", path=test_mount_point)

        with open(utils.get_config_file_path("client-cert.pem")) as fp:
            certificate = fp.read()
            self.client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        # Test that we can createa role
        response = self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces="vault_test",
            mount_point=test_mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

        # Reset integration test state
        self.client.sys.disable_auth_method(path=test_mount_point)

    def test_get_kubernetes_role(self):
        test_role_name = "test_role"
        test_mount_point = "k8s"
        test_bound_service_account_namespaces = ["vault-test"]

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if f"{test_mount_point}/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method(test_mount_point)
        self.client.sys.enable_auth_method("kubernetes", path=test_mount_point)

        with open(utils.get_config_file_path("client-cert.pem")) as fp:
            certificate = fp.read()
            self.client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        # Test that we can createa role
        self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces=test_bound_service_account_namespaces,
            mount_point=test_mount_point,
        )
        response = self.client.get_kubernetes_role(
            name=test_role_name,
            mount_point=test_mount_point,
        )
        self.assertIn(
            member="data",
            container=response,
        )
        self.assertEqual(
            first=test_bound_service_account_namespaces,
            second=response["data"].get("bound_service_account_namespaces"),
        )
        # Reset integration test state
        self.client.sys.disable_auth_method(path=test_mount_point)

    def test_list_kubernetes_roles(self):
        test_role_name = "test_role"
        test_mount_point = "k8s"
        test_bound_service_account_namespaces = ["vault-test"]

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if f"{test_mount_point}/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method(test_mount_point)
        self.client.sys.enable_auth_method("kubernetes", path=test_mount_point)

        with open(utils.get_config_file_path("client-cert.pem")) as fp:
            certificate = fp.read()
            self.client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        # Test that we can createa role
        self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces=test_bound_service_account_namespaces,
            mount_point=test_mount_point,
        )
        response = self.client.list_kubernetes_roles(
            mount_point=test_mount_point,
        )
        self.assertIn(
            member="data",
            container=response,
        )
        self.assertEqual(first=[test_role_name], second=response["data"].get("keys"))
        # Reset integration test state
        self.client.sys.disable_auth_method(path=test_mount_point)

    def test_delete_kubernetes_role(self):
        test_role_name = "test_role"
        test_mount_point = "k8s"
        expected_status_code = 204

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if f"{test_mount_point}/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method(test_mount_point)
        self.client.sys.enable_auth_method("kubernetes", path=test_mount_point)

        with open(utils.get_config_file_path("client-cert.pem")) as fp:
            certificate = fp.read()
            self.client.create_kubernetes_configuration(
                kubernetes_host="127.0.0.1:80",
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces="vault_test",
            mount_point=test_mount_point,
        )
        # Test that we can delete a role
        response = self.client.delete_kubernetes_role(
            role=test_role_name,
            mount_point=test_mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

        # Reset integration test state
        self.client.sys.disable_auth_method(path=test_mount_point)

    def test_auth_kubernetes(self):
        test_role_name = "test_role"
        test_host = "127.0.0.1:80"
        test_mount_point = "k8s"

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if f"{test_mount_point}/" in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.disable_auth_method(test_mount_point)
        self.client.sys.enable_auth_method("kubernetes", path=test_mount_point)
        with open(utils.get_config_file_path("client-cert.pem")) as fp:
            certificate = fp.read()
            self.client.create_kubernetes_configuration(
                kubernetes_host=test_host,
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names="*",
            bound_service_account_namespaces="vault_test",
            mount_point=test_mount_point,
        )

        # Test that we can authenticate
        with open(utils.get_config_file_path("example.jwt")) as fp:
            test_jwt = fp.read()
            with self.assertRaises(
                exceptions.InternalServerError
            ) as assertRaisesContext:
                # we don't actually have a valid JWT to provide, so this method will throw an exception
                self.client.auth_kubernetes(
                    role=test_role_name,
                    jwt=test_jwt,
                    mount_point=test_mount_point,
                )

        expected_exception_message = 'claim "iss" is invalid'
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertIn(expected_exception_message, actual_exception_message)

        # Reset integration test state
        self.client.sys.disable_auth_method(path=test_mount_point)

    def test_seal_status(self):
        seal_status_property = self.client.seal_status
        logging.debug("seal_status_property: %s" % seal_status_property)
        self.assertIn(
            member="sealed",
            container=seal_status_property,
        )

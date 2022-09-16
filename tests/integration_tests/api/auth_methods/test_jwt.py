import logging
from unittest import TestCase

from parameterized import param, parameterized

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestJWT(HvacIntegrationTestCase, TestCase):
    TEST_APPROLE_PATH = "jwt-test-approle"
    TEST_APPROLE_ROLE_ID = "jwt-test-role-id"
    TEST_JWT_PATH = "jwt-test"
    oidc_client_id = "hvac-client-id"
    oidc_server = None

    def setUp(self):
        super().setUp()
        self.client.sys.enable_auth_method(
            method_type="jwt",
            path=self.TEST_JWT_PATH,
        )

    def tearDown(self):
        super().tearDown()
        self.client.sys.disable_auth_method(
            path=self.TEST_JWT_PATH,
        )
        self.client.sys.disable_auth_method(
            path=self.TEST_APPROLE_PATH,
        )
        if self.oidc_server:
            self.oidc_server.shutdown()
            self.oidc_server = None

    @parameterized.expand(
        [
            param(
                "configure using vault identity OIDC",
                issuer="https://localhost:8200",
            ),
        ]
    )
    def test_configure(self, label, issuer):
        oidc_discovery_url = f"{issuer}/v1/identity/oidc"
        self.client.secrets.identity.configure_tokens_backend(
            issuer=issuer,
        )
        response = self.client.auth.jwt.configure(
            oidc_discovery_url=oidc_discovery_url,
            oidc_discovery_ca_pem="".join(
                open(utils.get_config_file_path("server-cert.pem")).readlines()
            ),
            path=self.TEST_JWT_PATH,
        )
        logging.debug("configure response: %s" % response)
        self.assertEqual(
            first=204,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            param(
                "configure using vault identity OIDC",
                issuer="https://localhost:8200",
            ),
        ]
    )
    def test_read_config(self, label, issuer):
        oidc_discovery_url = f"{issuer}/v1/identity/oidc"
        self.client.secrets.identity.configure_tokens_backend(
            issuer=issuer,
        )
        configure_response = self.client.auth.jwt.configure(
            oidc_discovery_url=oidc_discovery_url,
            oidc_discovery_ca_pem="".join(
                open(utils.get_config_file_path("server-cert.pem")).readlines()
            ),
            path=self.TEST_JWT_PATH,
        )
        logging.debug("configure response: %s" % configure_response)
        response = self.client.auth.jwt.read_config(
            path=self.TEST_JWT_PATH,
        )
        logging.debug("read_config response: %s" % response)
        self.assertEqual(
            first=oidc_discovery_url,
            second=response["data"]["oidc_discovery_url"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                role_name="hvac",
                allowed_redirect_uris=["https://localhost:8200/jwt-test/callback"],
                user_claim="https://vault/user",
            ),
        ]
    )
    def test_create_role(self, label, role_name, allowed_redirect_uris, user_claim):
        response = self.client.auth.jwt.create_role(
            name=role_name,
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            bound_audiences=["1234"],
            path=self.TEST_JWT_PATH,
        )
        logging.debug("create_role response: %s" % response)
        if utils.vault_version_lt("1.11"):
            self.assertIn(
                member="data",
                container=response,
            )
        else:
            self.assertEqual(
                204,
                response.status_code,
            )

    @parameterized.expand(
        [
            param(
                "success",
                role_name="hvac",
                allowed_redirect_uris=["https://localhost:8200/jwt-test/callback"],
                user_claim="https://vault/user",
            ),
        ]
    )
    def test_read_role(self, label, role_name, allowed_redirect_uris, user_claim):
        create_role_response = self.client.auth.jwt.create_role(
            name=role_name,
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            bound_audiences=["1234"],
            path=self.TEST_JWT_PATH,
        )
        logging.debug("create_role_response: %s" % create_role_response)
        response = self.client.auth.jwt.read_role(
            name=role_name,
            path=self.TEST_JWT_PATH,
        )
        logging.debug("read_role response: %s" % response)
        self.assertEqual(
            first=user_claim,
            second=response["data"]["user_claim"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                role_name="hvac",
                allowed_redirect_uris=["https://localhost:8200/jwt-test/callback"],
                user_claim="https://vault/user",
            ),
        ]
    )
    def test_list_roles(self, label, role_name, allowed_redirect_uris, user_claim):
        create_role_response = self.client.auth.jwt.create_role(
            name=role_name,
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            bound_audiences=["1234"],
            path=self.TEST_JWT_PATH,
        )
        logging.debug("create_role_response: %s" % create_role_response)
        response = self.client.auth.jwt.list_roles(
            path=self.TEST_JWT_PATH,
        )
        logging.debug("list_roles response: %s" % response)
        self.assertIn(
            member=role_name,
            container=response["data"]["keys"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                role_name="hvac",
                allowed_redirect_uris=["https://localhost:8200/jwt-test/callback"],
                user_claim="https://vault/user",
            ),
        ]
    )
    def test_delete_role(self, label, role_name, allowed_redirect_uris, user_claim):
        create_role_response = self.client.auth.jwt.create_role(
            name=role_name,
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            bound_audiences=["1234"],
            path=self.TEST_JWT_PATH,
        )
        logging.debug("create_role_response: %s" % create_role_response)
        response = self.client.auth.jwt.delete_role(
            name=role_name,
            path=self.TEST_JWT_PATH,
        )
        logging.debug("delete_role response: %s" % response)
        self.assertEqual(
            first=204,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            param(
                "success",
                issuer="https://localhost:8200",
                role_name="hvac-jwt",
                allowed_redirect_uris=["https://localhost:8200/jwt-test/oidc/callback"],
                user_claim="sub",
            ),
        ]
    )
    def test_jwt_login(
        self, label, issuer, role_name, allowed_redirect_uris, user_claim
    ):
        if "%s/" % self.TEST_APPROLE_PATH not in self.client.sys.list_auth_methods():
            self.client.sys.enable_auth_method(
                method_type="approle",
                path=self.TEST_APPROLE_PATH,
            )
        id_token_role_name = "hvac-jwt-test"
        key_name = "jwt-test-key"
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=key_name,
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        create_or_update_role_response = (
            self.client.secrets.identity.create_or_update_role(
                name=id_token_role_name,
                key=key_name,
            )
        )
        logging.debug(
            "create_or_update_role response: %s" % create_or_update_role_response
        )
        read_role_response = self.client.secrets.identity.read_role(
            name=id_token_role_name,
        )
        logging.debug("read_role response: %s" % read_role_response)
        token_client_id = read_role_response["data"]["client_id"]
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=key_name,
            allowed_client_ids=[
                token_client_id,
            ],
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)

        self.client.secrets.identity.configure_tokens_backend(
            issuer="https://localhost:8200",
        )
        response = self.client.auth.jwt.configure(
            jwks_url="https://localhost:8200/v1/identity/oidc/.well-known/keys",
            jwks_ca_pem="".join(
                open(utils.get_config_file_path("server-cert.pem")).readlines()
            ),
            path=self.TEST_JWT_PATH,
        )
        logging.debug("configure response: %s" % response)
        create_role_response = self.client.auth.jwt.create_role(
            name=role_name,
            role_type="jwt",
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            bound_audiences=[token_client_id],
            path=self.TEST_JWT_PATH,
        )
        logging.debug("create_role_response: %s" % create_role_response)

        # Log in using a dummy approle role so our client token has an associated identity
        self.login_using_admin_approle_role(
            role_id=self.TEST_APPROLE_ROLE_ID,
            path=self.TEST_APPROLE_PATH,
        )
        generate_token_response = self.client.secrets.identity.generate_signed_id_token(
            name=id_token_role_name,
        )
        logging.debug("generate_token_response: %s" % generate_token_response)

        read_well_known_configurations_response = (
            self.client.secrets.identity.read_well_known_configurations()
        )
        logging.debug(
            "read_well_known_configurations_response: %s"
            % read_well_known_configurations_response
        )
        response = self.client.auth.jwt.jwt_login(
            role=role_name,
            jwt=generate_token_response["data"]["token"],
            path=self.TEST_JWT_PATH,
        )
        logging.debug("jwt_login response: %s" % response)
        self.client.token = response["auth"]["client_token"]
        self.assertIn(
            member=role_name,
            container=self.client.lookup_token()["data"]["meta"]["role"],
        )

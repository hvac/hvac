import logging
from unittest import TestCase
from urllib.parse import parse_qs, urlparse

from parameterized import param, parameterized
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase
from tests.utils.mock_oauth_provider.mock_oauth_provider import (
    MockOauthProviderServerThread,
    create_user_session_and_client,
)


class TestOIDC(HvacIntegrationTestCase, TestCase):
    TEST_APPROLE_PATH = "oidc-test-approle"
    TEST_APPROLE_ROLE_ID = "oidc-test-role-id"
    TEST_OIDC_PATH = "oidc-test"
    oidc_client_id = "hvac-client-id"
    oidc_server = None

    def setUp(self):
        super().setUp()
        self.client.sys.enable_auth_method(
            method_type="oidc",
            path=self.TEST_OIDC_PATH,
        )

    def tearDown(self):
        super().tearDown()
        self.client.sys.disable_auth_method(
            path=self.TEST_OIDC_PATH,
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
        response = self.client.auth.oidc.configure(
            oidc_discovery_url=oidc_discovery_url,
            oidc_discovery_ca_pem="".join(
                open(utils.get_config_file_path("server-cert.pem")).readlines()
            ),
            path=self.TEST_OIDC_PATH,
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
        configure_response = self.client.auth.oidc.configure(
            oidc_discovery_url=oidc_discovery_url,
            oidc_discovery_ca_pem="".join(
                open(utils.get_config_file_path("server-cert.pem")).readlines()
            ),
            path=self.TEST_OIDC_PATH,
        )
        logging.debug("configure response: %s" % configure_response)
        response = self.client.auth.oidc.read_config(
            path=self.TEST_OIDC_PATH,
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
                allowed_redirect_uris=["https://localhost:8200/oidc-test/callback"],
                user_claim="https://vault/user",
            ),
        ]
    )
    def test_read_role(self, label, role_name, allowed_redirect_uris, user_claim):
        create_role_response = self.client.auth.oidc.create_role(
            name=role_name,
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            path=self.TEST_OIDC_PATH,
        )
        logging.debug("create_role_response: %s" % create_role_response)
        response = self.client.auth.oidc.read_role(
            name=role_name,
            path=self.TEST_OIDC_PATH,
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
                allowed_redirect_uris=["https://localhost:8200/oidc-test/callback"],
                user_claim="https://vault/user",
            ),
        ]
    )
    def test_list_roles(self, label, role_name, allowed_redirect_uris, user_claim):
        create_role_response = self.client.auth.oidc.create_role(
            name=role_name,
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            path=self.TEST_OIDC_PATH,
        )
        logging.debug("create_role_response: %s" % create_role_response)
        response = self.client.auth.oidc.list_roles(
            path=self.TEST_OIDC_PATH,
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
                allowed_redirect_uris=["https://localhost:8200/oidc-test/callback"],
                user_claim="https://vault/user",
            ),
        ]
    )
    def test_delete_role(self, label, role_name, allowed_redirect_uris, user_claim):
        create_role_response = self.client.auth.oidc.create_role(
            name=role_name,
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            path=self.TEST_OIDC_PATH,
        )
        logging.debug("create_role_response: %s" % create_role_response)
        response = self.client.auth.oidc.delete_role(
            name=role_name,
            path=self.TEST_OIDC_PATH,
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
                role_name="hvac",
                allowed_redirect_uris=["https://localhost:8200/oidc-test/callback"],
                user_claim="https://vault/user",
            ),
        ]
    )
    def test_oidc_authorization_url_request(
        self, label, issuer, role_name, allowed_redirect_uris, user_claim
    ):
        if "%s/" % self.TEST_APPROLE_PATH not in self.client.sys.list_auth_methods():
            self.client.sys.enable_auth_method(
                method_type="approle",
                path=self.TEST_APPROLE_PATH,
            )
        id_token_role_name = "hvac-oidc-test"
        key_name = "oidc-test-key"
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=key_name,
        )
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
        # Log in using a dummy approle role so our client token has an associated identity
        self.login_using_admin_approle_role(
            role_id=self.TEST_APPROLE_ROLE_ID,
            path=self.TEST_APPROLE_PATH,
        )
        generate_token_response = self.client.secrets.identity.generate_signed_id_token(
            name=id_token_role_name,
        )
        logging.debug("generate_token_response: %s" % generate_token_response)

        oidc_discovery_url = f"{issuer}/v1/identity/oidc"
        self.client.secrets.identity.configure_tokens_backend(
            issuer=issuer,
        )
        response = self.client.auth.oidc.configure(
            oidc_discovery_url=oidc_discovery_url,
            oidc_discovery_ca_pem="".join(
                open(utils.get_config_file_path("server-cert.pem")).readlines()
            ),
            oidc_client_id=self.oidc_client_id,
            oidc_client_secret=generate_token_response["data"]["token"],
            path=self.TEST_OIDC_PATH,
        )
        logging.debug("configure response: %s" % response)
        create_role_response = self.client.auth.oidc.create_role(
            name=role_name,
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            path=self.TEST_OIDC_PATH,
        )
        logging.debug("create_role_response: %s" % create_role_response)
        response = self.client.auth.oidc.oidc_authorization_url_request(
            role=role_name,
            redirect_uri=allowed_redirect_uris[0],
            path=self.TEST_OIDC_PATH,
        )
        logging.debug("oidc_authorization_url_request response: %s" % response)
        self.assertIn(
            member=f"?client_id={self.oidc_client_id}",
            container=response["data"]["auth_url"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                role_name="hvac-oidc",
                allowed_redirect_uris=[
                    "https://localhost:8200/v1/auth/oidc-test/oidc/callback"
                ],
                user_claim="sub",
            ),
        ]
    )
    def test_oidc_callback(self, label, role_name, allowed_redirect_uris, user_claim):
        self.oidc_server = MockOauthProviderServerThread()
        self.oidc_server.start()
        oidc_details = create_user_session_and_client(
            server_url=self.oidc_server.url,
            oauth_redirect_uri=allowed_redirect_uris[0],
        )

        response = self.client.auth.oidc.configure(
            oidc_discovery_url=oidc_details["discovery_url"],
            oidc_response_mode="form_post",
            oidc_response_types=["code"],
            oidc_discovery_ca_pem="".join(
                open(utils.get_config_file_path("server-cert.pem")).readlines()
            ),
            oidc_client_id=oidc_details["client_id"],
            oidc_client_secret=oidc_details["client_secret"],
            path=self.TEST_OIDC_PATH,
        )
        logging.debug("oidc.configure response: %s" % response)

        create_role_response = self.client.auth.oidc.create_role(
            name=role_name,
            role_type="oidc",
            allowed_redirect_uris=allowed_redirect_uris,
            user_claim=user_claim,
            verbose_oidc_logging=True,
            path=self.TEST_OIDC_PATH,
        )
        logging.debug("create_role_response: %s" % create_role_response)

        oidc_authorization_url_response = (
            self.client.auth.oidc.oidc_authorization_url_request(
                role=role_name,
                redirect_uri=allowed_redirect_uris[0],
                path=self.TEST_OIDC_PATH,
            )
        )
        logging.debug(
            "oidc_authorization_url_request response: %s"
            % oidc_authorization_url_response
        )

        auth_url = oidc_authorization_url_response["data"]["auth_url"]
        logging.debug("auth_url: %s" % auth_url)
        auth_url_qs = urlparse(auth_url).query
        auth_url_qs_parsed = parse_qs(auth_url_qs)
        logging.debug("auth_url_qs_parsed: %s" % auth_url_qs_parsed)

        authorize_response = oidc_details["session"].get(
            url=auth_url,
        )
        logging.debug("authorize_response: %s" % authorize_response.json())
        authorization = authorize_response.json()
        logging.debug("authorization: %s" % authorization)

        client_cert_path = utils.get_config_file_path("client-cert.pem")
        client_key_path = utils.get_config_file_path("client-key.pem")
        server_cert_path = utils.get_config_file_path("server-cert.pem")
        response = oidc_details["session"].post(
            url=auth_url,
            cert=(client_cert_path, client_key_path),
            verify=server_cert_path,
            data=dict(confirm=True),
        )
        oidc_auth_data = response.json()
        logging.debug("oidc_auth_data: %s" % oidc_auth_data)
        self.client.token = oidc_auth_data["auth"]["client_token"]
        self.assertIn(
            member=role_name,
            container=self.client.lookup_token()["data"]["meta"]["role"],
        )

import logging
from http.server import HTTPServer
from threading import Thread
from unittest import TestCase

from hvac import exceptions
from parameterized import parameterized
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase
from tests.utils.mock_github_request_handler import MockGithubRequestHandler


class TestGithub(HvacIntegrationTestCase, TestCase):
    TEST_GITHUB_PATH = "test-github"

    @classmethod
    def setUpClass(cls):
        try:
            super().setUpClass()

            # Configure mock server.
            cls.mock_server_port = utils.get_free_port()
            cls.mock_server = HTTPServer(
                ("localhost", cls.mock_server_port), MockGithubRequestHandler
            )

            # Start running mock server in a separate thread.
            # Daemon threads automatically shut down when the main process exits.
            cls.mock_server_thread = Thread(target=cls.mock_server.serve_forever)
            cls.mock_server_thread.daemon = True
            cls.mock_server_thread.start()
        except Exception:
            # Ensure that Vault server is taken down if setUpClass fails
            super().tearDownClass()
            raise

    def setUp(self):
        super().setUp()
        self.client.sys.enable_auth_method(
            method_type="github",
            path=self.TEST_GITHUB_PATH,
        )

    def tearDown(self):
        super().tearDown()
        self.client.sys.disable_auth_method(
            path=self.TEST_GITHUB_PATH,
        )

    @parameterized.expand(
        [
            (
                "just organization",
                True,
                "some-test-org",
                0,
                0,
                TEST_GITHUB_PATH,
            ),
        ]
    )
    def test_configure(
        self,
        test_label,
        expected_value,
        organization,
        ttl,
        max_ttl,
        mount_point,
    ):
        response = self.client.auth.github.configure(
            organization=organization,
            base_url=f"http://localhost:{self.mock_server_port}/",
            ttl=ttl,
            max_ttl=max_ttl,
            mount_point=mount_point,
        )
        self.assertEqual(
            first=expected_value,
            second=bool(response),
        )

    @parameterized.expand(
        [
            ("just organization", "some-test-org", "", ""),
            ("custom ttl seconds", "some-test-org", "500s", ""),
            ("custom ttl minutes", "some-test-org", "500m", ""),
            ("custom ttl hours", "some-test-org", "500h", ""),
            ("custom max ttl", "some-test-org", "", "500s"),
        ]
    )
    def test_configure_and_read_configuration(
        self, test_label, organization, ttl, max_ttl
    ):
        config_response = self.client.auth.github.configure(
            organization=organization,
            base_url=f"http://localhost:{self.mock_server_port}/",
            ttl=ttl,
            max_ttl=max_ttl,
            mount_point=self.TEST_GITHUB_PATH,
        )
        logging.debug(f"config_response: {config_response}")
        self.assertEqual(first=204, second=config_response.status_code)

        read_config_response = self.client.auth.github.read_configuration(
            mount_point=self.TEST_GITHUB_PATH,
        )
        logging.debug(f"read_config_response: {read_config_response}")
        self.assertEqual(
            first=organization, second=read_config_response["data"]["organization"]
        )
        ttl_data_key = "token_ttl" if utils.vault_version_ge("1.2.0") else "ttl"
        max_ttl_data_key = (
            "token_max_ttl" if utils.vault_version_ge("1.2.0") else "max_ttl"
        )
        self.assertEqual(
            first=self.convert_python_ttl_value_to_expected_vault_response(
                ttl_value=ttl
            ),
            second=read_config_response["data"][ttl_data_key],
        )
        self.assertEqual(
            first=self.convert_python_ttl_value_to_expected_vault_response(
                ttl_value=max_ttl
            ),
            second=read_config_response["data"][max_ttl_data_key],
        )

    @parameterized.expand(
        [
            ("no policies", True, "hvac", None),
            ("with policies", True, "hvac", ["default"]),
        ]
    )
    def test_map_team(self, test_label, expected_value, team_name, policies):
        response = self.client.auth.github.map_team(
            team_name=team_name,
            policies=policies,
            mount_point=self.TEST_GITHUB_PATH,
        )
        self.assertEqual(
            first=expected_value,
            second=bool(response),
        )

    def test_read_team_mapping(self):
        response = self.client.auth.github.read_team_mapping(
            team_name="hvac",
            mount_point=self.TEST_GITHUB_PATH,
        )
        self.assertIn(
            member="data",
            container=response,
        )

    @parameterized.expand(
        [
            ("no policies", True, "hvac", None),
            ("with policy", True, "hvac", ["default"]),
            (
                "with policy incorrect type",
                True,
                "hvac",
                "default, root",
                exceptions.ParamValidationError,
                "unsupported policies argument provided",
            ),
            ("with policies", True, "hvac", ["default", "root"]),
        ]
    )
    def test_map_team_and_read_mapping(
        self,
        test_label,
        expected_value,
        team_name,
        policies,
        raises=False,
        exception_msg="",
    ):

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.github.map_team(
                    team_name=team_name,
                    policies=policies,
                    mount_point=self.TEST_GITHUB_PATH,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            response = self.client.auth.github.map_team(
                team_name=team_name,
                policies=policies,
                mount_point=self.TEST_GITHUB_PATH,
            )
            self.assertEqual(
                first=expected_value,
                second=bool(response),
            )

            response = self.client.auth.github.read_team_mapping(
                team_name=team_name,
                mount_point=self.TEST_GITHUB_PATH,
            )
            if policies is None:
                expected_policies = ""
            else:
                expected_policies = ",".join(policies)

            self.assertDictEqual(
                d1=dict(key=team_name, value=expected_policies),
                d2=response["data"],
            )

    @parameterized.expand(
        [
            ("no policies", True, "hvac-user", None),
            ("with policies", True, "hvac-user", ["default"]),
        ]
    )
    def teat_map_user(self, test_label, expected_value, user_name, policies):
        response = self.client.auth.github.map_user(
            user_name=user_name,
            policies=policies,
            mount_point=self.TEST_GITHUB_PATH,
        )
        self.assertEqual(
            first=expected_value,
            second=bool(response),
        )

    def test_read_user_mapping(self):
        response = self.client.auth.github.read_user_mapping(
            user_name="hvac",
            mount_point=self.TEST_GITHUB_PATH,
        )
        self.assertIn(
            member="data",
            container=response,
        )

    @parameterized.expand(
        [
            ("no policies", True, "hvac", None),
            ("with policy", True, "hvac", ["default"]),
            (
                "with policy incorrect type",
                True,
                "hvac",
                "default, root",
                exceptions.ParamValidationError,
                "unsupported policies argument provided",
            ),
            ("with policies", True, "hvac", ["default", "root"]),
        ]
    )
    def test_map_user_and_read_mapping(
        self,
        test_label,
        expected_value,
        user_name,
        policies,
        raises=False,
        exception_msg="",
    ):

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.github.map_user(
                    user_name=user_name,
                    policies=policies,
                    mount_point=self.TEST_GITHUB_PATH,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            response = self.client.auth.github.map_user(
                user_name=user_name,
                policies=policies,
                mount_point=self.TEST_GITHUB_PATH,
            )
            self.assertEqual(
                first=expected_value,
                second=bool(response),
            )

            response = self.client.auth.github.read_user_mapping(
                user_name=user_name,
                mount_point=self.TEST_GITHUB_PATH,
            )
            if policies is None:
                expected_policies = ""
            else:
                expected_policies = ",".join(policies)

            self.assertDictEqual(
                d1=dict(key=user_name, value=expected_policies),
                d2=response["data"],
            )

    @parameterized.expand(
        [
            ("valid token", "valid-token", None, None),
            (
                "invalid token not in org",
                "invalid-token",
                exceptions.InvalidRequest
                if utils.vault_version_lt("1.10.0")
                else exceptions.InternalServerError,
                "user is not part of required org",
            ),
        ]
    )
    def test_login(self, test_label, test_token, exceptions_raised, exception_msg):
        self.client.auth.github.configure(
            organization="hvac",
            base_url=f"http://localhost:{self.mock_server_port}/",
            mount_point=self.TEST_GITHUB_PATH,
        )
        if exceptions_raised is None:
            self.client.auth.github.login(
                token=test_token,
                mount_point=self.TEST_GITHUB_PATH,
            )
        else:
            with self.assertRaises(exceptions_raised) as cm:
                self.client.auth.github.login(
                    token=test_token,
                    mount_point=self.TEST_GITHUB_PATH,
                )
            self.assertIn(member=exception_msg, container=str(cm.exception))

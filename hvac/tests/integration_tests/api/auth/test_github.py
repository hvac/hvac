from unittest import TestCase

from parameterized import parameterized
from hvac import exceptions
from hvac.api.auth.github import DEFAULT_MOUNT_POINT
from hvac.tests import utils
from threading import Thread
try:
    # Python 2.7
    from http.server import HTTPServer
except ImportError:
    # Python 3.x
    from BaseHTTPServer import HTTPServer


class TestGithub(utils.HvacIntegrationTestCase, TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestGithub, cls).setUpClass()
        # Configure mock server.
        cls.mock_server_port = utils.get_free_port()
        cls.mock_server = HTTPServer(('localhost', cls.mock_server_port), utils.MockGithubRequestHandler)

        # Start running mock server in a separate thread.
        # Daemon threads automatically shut down when the main process exits.
        cls.mock_server_thread = Thread(target=cls.mock_server.serve_forever)
        cls.mock_server_thread.setDaemon(True)
        cls.mock_server_thread.start()

    def setUp(self):
        super(TestGithub, self).setUp()
        if 'github/' not in self.client.list_auth_backends():
            self.client.enable_auth_backend(
                backend_type='github',
            )

    def tearDown(self):
        super(TestGithub, self).tearDown()
        for mount_point, configuration in self.client.list_auth_backends()['data'].items():
            if configuration.get('type') == 'github':
                self.client.disable_auth_backend(
                    mount_point=mount_point,
                )

    @parameterized.expand([
        ("just organization", 204, 'some-test-org', '', 0, 0, DEFAULT_MOUNT_POINT),
    ])
    def test_configure(self, test_label, expected_status_code, organization, base_url, ttl, max_ttl, mount_point):
        response = self.client.github.configure(
            organization=organization,
            base_url=base_url,
            ttl=ttl,
            max_ttl=max_ttl,
            mount_point=mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code
        )

    def test_read_configuration(self):
        response = self.client.github.read_configuration()
        self.assertIn(
            member='data',
            container=response,
        )

    @parameterized.expand([
        ("just organization", 'some-test-org', '', '', ''),
        ("different base url", 'some-test-org', 'https://cathub.example', '', ''),
        ("custom ttl seconds", 'some-test-org', '', '500s', ''),
        ("custom ttl minutes", 'some-test-org', '', '500m', ''),
        ("custom ttl hours", 'some-test-org', '', '500h', ''),
        ("custom max ttl", 'some-test-org', '', '', '500s'),
    ])
    def test_configure_and_read_configuration(self, test_label, organization, base_url, ttl, max_ttl):
        config_response = self.client.github.configure(
            organization=organization,
            base_url=base_url,
            ttl=ttl,
            max_ttl=max_ttl,
        )
        self.assertEqual(
            first=204,
            second=config_response.status_code
        )

        read_config_response = self.client.github.read_configuration()
        self.assertEqual(
            first=organization,
            second=read_config_response['data']['organization']
        )
        self.assertEqual(
            first=base_url,
            second=read_config_response['data']['base_url']
        )
        self.assertEqual(
            first=self.convert_python_ttl_value_to_expected_vault_response(ttl_value=ttl),
            second=read_config_response['data']['ttl']
        )
        self.assertEqual(
            first=self.convert_python_ttl_value_to_expected_vault_response(ttl_value=max_ttl),
            second=read_config_response['data']['max_ttl']
        )

    @parameterized.expand([
        ("no policies", 204, 'hvac', None),
        ("with policies", 204, 'hvac', ['default']),
    ])
    def test_map_team(self, test_label, expected_status_code, team_name, policies):
        response = self.client.github.map_team(
            team_name=team_name,
            policies=policies,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code
        )

    def test_read_team_mapping(self):
        response = self.client.github.read_team_mapping(
            team_name='hvac',
        )
        self.assertIn(
            member='data',
            container=response,
        )

    @parameterized.expand([
        ("no policies", 204, 'hvac', None),
        ("with policy", 204, 'hvac', ['default']),
        ("with policies", 204, 'hvac', ['default', 'root']),
    ])
    def test_map_team_and_read_mapping(self, test_label, expected_status_code, team_name, policies):
        response = self.client.github.map_team(
            team_name=team_name,
            policies=policies,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code
        )

        response = self.client.github.read_team_mapping(
            team_name=team_name,
        )
        if policies is None:
            expected_policies = ''
        else:
            expected_policies = ','.join(policies)

        self.assertDictEqual(
            d1=dict(key=team_name, value=expected_policies),
            d2=response['data'],
        )

    @parameterized.expand([
        ("no policies", 204, 'hvac-user', None),
        ("with policies", 204, 'hvac-user', ['default']),
    ])
    def teat_map_user(self, test_label, expected_status_code, user_name, policies):
        response = self.client.github.map_user(
            user_name=user_name,
            policies=policies,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code
        )

    def test_read_user_mapping(self):
        response = self.client.github.read_user_mapping(
            user_name='hvac',
        )
        self.assertIn(
            member='data',
            container=response,
        )

    @parameterized.expand([
        ("no policies", 204, 'hvac', None),
        ("with policy", 204, 'hvac', ['default']),
        ("with policies", 204, 'hvac', ['default', 'root']),
    ])
    def test_map_user_and_read_mapping(self, test_label, expected_status_code, user_name, policies):
        response = self.client.github.map_user(
            user_name=user_name,
            policies=policies,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code
        )

        response = self.client.github.read_user_mapping(
            user_name=user_name,
        )
        if policies is None:
            expected_policies = ''
        else:
            expected_policies = ','.join(policies)

        self.assertDictEqual(
            d1=dict(key=user_name, value=expected_policies),
            d2=response['data'],
        )

    @parameterized.expand([
        ("valid token", 'valid-token', None, None),
        ("invalid token not in org", "invalid-token", exceptions.InvalidRequest, 'user is not part of required org'),
    ])
    def test_login(self, test_label, test_token, exceptions_raised, exception_msg):
        self.client.github.configure(
            organization='hvac',
            base_url='http://localhost:{port}/'.format(port=self.mock_server_port)
        )
        if exceptions_raised is None:
            self.client.github.login(
                token=test_token
            )
        else:
            with self.assertRaises(exceptions_raised) as cm:
                self.client.github.login(
                    token=test_token
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception)
            )

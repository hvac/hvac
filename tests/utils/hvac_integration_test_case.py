#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import warnings

from mock import patch
from tests.utils import ServerManager, get_config_file_path, create_client


class HvacIntegrationTestCase(object):
    """Base class intended to be used by all hvac integration test cases."""

    manager = None
    client = None
    mock_warnings = None

    @classmethod
    def setUpClass(cls):
        """Use the ServerManager class to launch a vault server process."""
        cls.manager = ServerManager(
            config_path=get_config_file_path('vault-tls.hcl'),
            client=create_client()
        )
        cls.manager.start()
        cls.manager.initialize()
        cls.manager.unseal()

    @classmethod
    def tearDownClass(cls):
        """Stop the vault server process at the conclusion of a test class."""
        cls.manager.stop()

    def setUp(self):
        """Set the client attribute to an authenticated hvac Client instance."""
        self.client = create_client(token=self.manager.root_token)

        # Squelch deprecating warnings during tests as we may want to deliberately call deprecated methods and/or verify
        # warnings invocations.
        warnings_patcher = patch('hvac.utils.warnings', spec=warnings)
        self.mock_warnings = warnings_patcher.start()

    def tearDown(self):
        """Ensure the hvac Client instance's root token is reset after any auth method tests that may have modified it.

        This allows subclass's to include additional tearDown logic to reset the state of the vault server when needed.
        """
        self.client.token = self.manager.root_token

    @staticmethod
    def convert_python_ttl_value_to_expected_vault_response(ttl_value):
        """Convert any acceptable Vault TTL *input* to the expected value that Vault would return.

        Vault accepts TTL values in the form r'^(?P<duration>[0-9]+)(?P<unit>[smh])?$ (number of seconds/minutes/hours).
            However it returns those values as integers corresponding to seconds when retrieving configuration.
            This method converts the "go duration format" arguments Vault accepts into the number (integer) of seconds
            corresponding to what Vault returns.

        :param ttl_value: A TTL string accepted by vault; number of seconds/minutes/hours
        :type ttl_value: string
        :return: The provided TTL value in the form returned by the Vault API.
        :rtype: int
        """
        expected_ttl = ttl_value
        if not isinstance(ttl_value, int) and ttl_value != '':
            regexp_matches = re.match(r'^(?P<duration>[0-9]+)(?P<unit>[smh])?$', ttl_value)
            if regexp_matches:
                fields = regexp_matches.groupdict()
                expected_ttl = int(fields['duration'])
                if fields['unit'] == 'm':
                    # convert minutes to seconds
                    expected_ttl = expected_ttl * 60
                elif fields['unit'] == 'h':
                    # convert hours to seconds
                    expected_ttl = expected_ttl * 60 * 60
        elif ttl_value == '':
            expected_ttl = 0
        return expected_ttl

    def prep_policy(self, name):
        """Add a common policy used by a subset of integration test cases."""
        text = """
        path "sys" {
            policy = "deny"
        }
            path "secret" {
        policy = "write"
        }
        """
        obj = {
            'path': {
                'sys': {
                    'policy': 'deny'},
                'secret': {
                    'policy': 'write'}
            }
        }
        self.client.set_policy(name, text)
        return text, obj

    def configure_pki(self, common_name='hvac.com', role_name='my-role', mount_point='pki'):
        """Helper function to configure a pki backend for integration tests that need to work with lease IDs.

        :param common_name: Common name to configure in the pki backend
        :type common_name: str
        :param role_name: Name of the test role to configure.
        :type role_name: str
        :param mount_point: The path the pki backend is mounted under.
        :type mount_point: str
        :return: Nothing.
        :rtype: None.
        """
        if '{path}/'.format(path=mount_point) in self.client.list_secret_backends():
            self.client.disable_secret_backend(mount_point)

        self.client.enable_secret_backend(backend_type='pki', mount_point=mount_point)

        self.client.write(
            path='{path}/root/generate/internal'.format(path=mount_point),
            common_name=common_name,
            ttl='8760h',
        )
        self.client.write(
            path='{path}/config/urls'.format(path=mount_point),
            issuing_certificates="http://127.0.0.1:8200/v1/pki/ca",
            crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl",
        )
        self.client.write(
            path='{path}/roles/{name}'.format(path=mount_point, name=role_name),
            allowed_domains=common_name,
            allow_subdomains=True,
            generate_lease=True,
            max_ttl='72h',
        )

    def disable_pki(self, mount_point='pki'):
        """Disable a previously configured pki backend.

        :param mount_point: The path the pki backend is mounted under.
        :type mount_point: str
        """
        self.client.disable_secret_backend(mount_point)

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import re
import warnings

from mock import patch

from tests.utils import get_config_file_path, create_client
from tests.utils.server_manager import ServerManager
import distutils.spawn


class HvacIntegrationTestCase(object):
    """Base class intended to be used by all hvac integration test cases."""

    manager = None
    client = None
    mock_warnings = None
    enable_vault_ha = False

    @classmethod
    def setUpClass(cls):
        """Use the ServerManager class to launch a vault server process."""
        config_paths = [get_config_file_path('vault-tls.hcl')]
        if distutils.spawn.find_executable('consul') is None and cls.enable_vault_ha:
            logging.warning('Unable to run Vault in HA mode, consul binary not found in path.')
            cls.enable_vault_ha = False
        if cls.enable_vault_ha:
            config_paths = [
                get_config_file_path('vault-ha-node1.hcl'),
                get_config_file_path('vault-ha-node2.hcl'),
            ]
        cls.manager = ServerManager(
            config_paths=config_paths,
            client=create_client(),
            use_consul=cls.enable_vault_ha,
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
        expected_ttl = 0
        if not isinstance(ttl_value, int) and ttl_value != '':
            regexp_matches = re.findall(r'(?P<duration>[0-9]+)(?P<unit>[smh])', ttl_value)
            if regexp_matches:
                for regexp_match in regexp_matches:
                    duration, unit = regexp_match
                    if unit == 'm':
                        # convert minutes to seconds
                        expected_ttl += int(duration) * 60
                    elif unit == 'h':
                        # convert hours to seconds
                        expected_ttl += int(duration) * 60 * 60
                    else:
                        expected_ttl += int(duration)

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

    def get_vault_addr_by_standby_status(self, standby_status=True):
        """Get an address for a Vault HA node currently in standby.

        :param standby_status: Value of the 'standby' key from the health status response to match.
        :type standby_status: bool
        :return: Standby Vault address.
        :rtype: str
        """
        vault_addresses = self.manager.get_active_vault_addresses()
        for vault_address in vault_addresses:
            health_status = create_client(url=vault_address).sys.read_health_status(method='GET')
            if health_status['standby'] == standby_status:
                return vault_address

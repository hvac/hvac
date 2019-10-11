#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import re
import warnings

from mock import patch

from tests.utils import get_config_file_path, create_client, is_enterprise
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
        if is_enterprise():
            # TODO: figure out why this bit isn't working
            logging.warning('Unable to run Vault in HA mode, enterprise Vault version not currently supported.')
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
        try:
            cls.manager.start()
            cls.manager.initialize()
            cls.manager.unseal()
        except Exception:
            cls.manager.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        """Stop the vault server process at the conclusion of a test class."""
        if cls.manager:
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

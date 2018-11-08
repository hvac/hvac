#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import subprocess
import time

from tests.utils import get_config_file_path

logger = logging.getLogger(__name__)


class ServerManager(object):
    """Runs vault process running with test configuration and associates a hvac Client instance with this process."""

    def __init__(self, config_path, client):
        """Set up class attributes for managing a vault server process.

        :param config_path: Full path to the Vault config to use when launching `vault server`.
        :type config_path: str
        :param client: Hvac Client that is used to initialize the vault server process.
        :type client: hvac.v1.Client
        """
        self.config_path = config_path
        self.client = client

        self.keys = None
        self.root_token = None

        self._process = None

    def start(self):
        """Launch the vault server process and wait until its online and initialized."""
        command = ['vault', 'server', '-config=' + self.config_path]

        self._process = subprocess.Popen(command,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)

        attempts_left = 20
        last_exception = None
        while attempts_left > 0:
            try:
                self.client.sys.is_initialized()
                return
            except Exception as ex:
                logger.debug('Waiting for Vault to start')

                time.sleep(0.5)

                attempts_left -= 1
                last_exception = ex

        raise Exception('Unable to start Vault in background: {0}'.format(last_exception))

    def stop(self):
        """Stop the vault server process being managed by this class."""
        self._process.kill()
        if os.getenv('HVAC_OUTPUT_VAULT_STDERR', False):
            _, stderr_lines = self._process.communicate()
            with open(get_config_file_path('vault_stderr.log'), 'w') as f:
                f.writelines(stderr_lines)

    def initialize(self):
        """Perform initialization of the vault server process and record the provided unseal keys and root token."""
        assert not self.client.sys.is_initialized()

        result = self.client.sys.initialize()

        self.root_token = result['root_token']
        self.keys = result['keys']

    def unseal(self):
        """Unseal the vault server process."""
        self.client.sys.submit_unseal_keys(self.keys)

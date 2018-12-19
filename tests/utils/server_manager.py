#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import subprocess
import time
import requests
import hcl

from tests.utils import get_config_file_path, load_config_file, create_client

logger = logging.getLogger(__name__)


class ServerManager(object):
    """Runs vault process running with test configuration and associates a hvac Client instance with this process."""

    def __init__(self, config_paths, client, use_consul=False):
        """Set up class attributes for managing a vault server process.

        :param config_paths: Full path to the Vault config to use when launching `vault server`.
        :type config_paths: list[str]
        :param client: Hvac Client that is used to initialize the vault server process.
        :type client: hvac.v1.Client
        """
        self.config_paths = config_paths
        self.client = client
        self.use_consul = use_consul

        self.keys = None
        self.root_token = None

        self._processes = []

    def start(self):
        """Launch the vault server process and wait until its online and initialized."""
        if self.use_consul:
            self.start_consul()

        cluster_initialized = False
        for config_path in self.config_paths:
            command = ['vault', 'server', '-config=' + config_path]
            logger.debug('Starting vault server with command: {cmd}'.format(cmd=command))
            self._processes.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))

            attempts_left = 20
            last_exception = None
            while attempts_left > 0 and not cluster_initialized:
                try:
                    self.client.sys.is_initialized()
                    cluster_initialized = True
                    break
                except Exception as ex:
                    logger.debug('Waiting for Vault to start')
                    time.sleep(0.5)
                    attempts_left -= 1
                    last_exception = ex
            if not cluster_initialized:
                raise Exception('Unable to start Vault in background: {0}'.format(last_exception))

    def start_consul(self):
        command = ['consul', 'agent', '-dev']
        logger.debug('Starting consul service with command: {cmd}'.format(cmd=command))
        self._processes.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        attempts_left = 20
        last_exception = None
        while attempts_left > 0:
            try:
                catalog_nodes_response = requests.get('http://127.0.0.1:8500/v1/catalog/nodes')
                nodes_list = catalog_nodes_response.json()
                logging.debug('JSON response from request to consul/v1/catalog/noses: {resp}'.format(resp=nodes_list))
                node_name = nodes_list[0]['Node']
                logging.debug('Current consul node name: {name}'.format(name=node_name))
                node_health_response = requests.get('http://127.0.0.1:8500/v1/health/node/{name}'.format(name=node_name))
                node_health = node_health_response.json()
                logging.debug('Node health response: {resp}'.format(resp=node_health))
                assert node_health[0]['Status'] == 'passing', 'Node {name} status != "passing"'.format(name=node_name)
                return True
            except Exception as error:
                logging.debug('Unable to connect to consul while waiting for process to start: {err}'.format(err=error))
                time.sleep(0.5)
                attempts_left -= 1
                last_exception = error

        raise Exception('Unable to start consul in background: {0}'.format(last_exception))

    def stop(self):
        """Stop the vault server process being managed by this class."""
        for process_num, process in enumerate(self._processes):
            process.kill()
            if os.getenv('HVAC_OUTPUT_VAULT_STDERR', False):
                _, stderr_lines = process.communicate()
                stderr_filename = 'vault{num}_stderr.log'.format(num=process_num)
                with open(get_config_file_path(stderr_filename), 'w') as f:
                    f.writelines(stderr_lines)

    def initialize(self):
        """Perform initialization of the vault server process and record the provided unseal keys and root token."""
        assert not self.client.sys.is_initialized()

        result = self.client.sys.initialize()

        self.root_token = result['root_token']
        self.keys = result['keys']

    def restart_vault_cluster(self):
        self.stop()
        self.start()
        self.initialize()

    def get_active_vault_addresses(self):
        vault_addresses = []
        for config_path in self.config_paths:
            config_hcl = load_config_file(config_path)
            config = hcl.loads(config_hcl)
            try:
                vault_address = 'https://{addr}'.format(addr=config['listener']['tcp']['address'])
            except KeyError as error:
                logger.error('Unable to find explict Vault address in config file {path}: {err}'.format(
                    path=config_path,
                    err=error,
                ))
                vault_address = 'https://127.0.0.1:8200'
                logger.debug('Using default address: {addr}'.format(addr=vault_address))
            vault_addresses.append(vault_address)
        return vault_addresses

    def unseal(self):
        """Unseal the vault server process."""
        vault_addresses = self.get_active_vault_addresses()
        for vault_address in vault_addresses:
            create_client(url=vault_address).sys.submit_unseal_keys(self.keys)

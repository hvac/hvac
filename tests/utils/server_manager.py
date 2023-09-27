#!/usr/bin/env python
import logging
import os
import subprocess
import time
import requests
import hcl

import distutils.spawn
from unittest import SkipTest
from tests.utils import get_config_file_path, load_config_file, create_client

logger = logging.getLogger(__name__)


class ServerManager:
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
        """Launch the vault server process and wait until its online and ready."""
        if self.use_consul:
            self.start_consul()

        if distutils.spawn.find_executable("vault") is None:
            raise SkipTest("Vault executable not found")

        # If a vault server is already running then we won't be able to start another one.
        # If we can't start our vault server then we don't know what we're testing against.
        try:
            self.client.sys.is_initialized()
        except Exception:
            pass
        else:
            raise Exception("Vault server already running")

        cluster_ready = False
        for config_path in self.config_paths:
            command = ["vault", "server", "-config=" + config_path]
            logger.debug(f"Starting vault server with command: {command}")
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            self._processes.append(process)
            logger.debug(f"Spawned vault server with PID {process.pid}")

            attempts_left = 20
            last_exception = None
            while attempts_left > 0 and not cluster_ready:
                try:
                    logger.debug("Checking if vault is ready...")
                    self.client.sys.is_initialized()
                    cluster_ready = True
                    break
                except Exception as ex:
                    if process.poll() is not None:
                        raise Exception("Vault server terminated before becoming ready")
                    logger.debug("Waiting for Vault to start")
                    time.sleep(0.5)
                    attempts_left -= 1
                    last_exception = ex
            if not cluster_ready:
                if process.poll() is None:
                    process.kill()
                stdout, stderr = process.communicate()
                raise Exception(
                    "Unable to start Vault in background:\n{err}\n{stdout}\n{stderr}".format(
                        err=last_exception,
                        stdout=stdout,
                        stderr=stderr,
                    )
                )

    def start_consul(self):
        if distutils.spawn.find_executable("consul") is None:
            raise SkipTest("Consul executable not found")

        try:
            requests.get("http://127.0.0.1:8500/v1/catalog/nodes")
        except Exception:
            pass
        else:
            raise Exception("Consul service already running")

        command = ["consul", "agent", "-dev"]
        logger.debug(f"Starting consul service with command: {command}")
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self._processes.append(process)
        attempts_left = 20
        last_exception = None
        while attempts_left > 0:
            try:
                catalog_nodes_response = requests.get(
                    "http://127.0.0.1:8500/v1/catalog/nodes"
                )
                nodes_list = catalog_nodes_response.json()
                logger.debug(
                    "JSON response from request to consul/v1/catalog/noses: {resp}".format(
                        resp=nodes_list
                    )
                )
                node_name = nodes_list[0]["Node"]
                logger.debug(f"Current consul node name: {node_name}")
                node_health_response = requests.get(
                    f"http://127.0.0.1:8500/v1/health/node/{node_name}"
                )
                node_health = node_health_response.json()
                logger.debug(f"Node health response: {node_health}")
                assert (
                    node_health[0]["Status"] == "passing"
                ), f'Node {node_name} status != "passing"'
                return True
            except Exception as error:
                if process.poll() is not None:
                    raise Exception("Consul service terminated before becoming ready")
                logger.debug(
                    "Unable to connect to consul while waiting for process to start: {err}".format(
                        err=error
                    )
                )
                time.sleep(0.5)
                attempts_left -= 1
                last_exception = error

        raise Exception(f"Unable to start consul in background: {last_exception}")

    def stop(self):
        """Stop the vault server process being managed by this class."""
        for process_num, process in enumerate(self._processes):
            logger.debug(f"Terminating vault server with PID {process.pid}")
            if process.poll() is None:
                process.kill()
            if os.getenv("HVAC_OUTPUT_VAULT_STDERR", False):
                stdout_lines, stderr_lines = process.communicate()
                stderr_filename = f"vault{process_num}_stderr.log"
                with open(get_config_file_path(stderr_filename), "w") as f:
                    logger.debug(stderr_lines.decode())
                    f.writelines(stderr_lines.decode())
                stdout_filename = f"vault{process_num}_stdout.log"
                with open(get_config_file_path(stdout_filename), "w") as f:
                    logger.debug(stdout_lines.decode())
                    f.writelines(stdout_lines.decode())

    def initialize(self):
        """Perform initialization of the vault server process and record the provided unseal keys and root token."""
        assert not self.client.sys.is_initialized()

        result = self.client.sys.initialize()

        self.root_token = result["root_token"]
        self.keys = result["keys"]

    def restart_vault_cluster(self, perform_init=True):
        self.stop()
        self.start()
        if perform_init:
            self.initialize()

    def get_active_vault_addresses(self):
        vault_addresses = []
        for config_path in self.config_paths:
            config_hcl = load_config_file(config_path)
            config = hcl.loads(config_hcl)
            try:
                vault_address = "https://{addr}".format(
                    addr=config["listener"]["tcp"]["address"]
                )
            except KeyError as error:
                logger.debug(
                    "Unable to find explicit Vault address in config file {path}: {err}".format(
                        path=config_path,
                        err=error,
                    )
                )
                vault_address = "https://127.0.0.1:8200"
                logger.debug(f"Using default address: {vault_address}")
            vault_addresses.append(vault_address)
        return vault_addresses

    def unseal(self):
        """Unseal the vault server process."""
        vault_addresses = self.get_active_vault_addresses()
        for vault_address in vault_addresses:
            create_client(url=vault_address).sys.submit_unseal_keys(self.keys)

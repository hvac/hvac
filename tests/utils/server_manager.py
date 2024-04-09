#!/usr/bin/env python
import logging
import os
import subprocess
import time
import requests
import hcl
import typing as t

import shutil
from unittest import SkipTest
from tests.utils import (
    get_config_file_path,
    load_config_file,
    create_client,
    PortGetter,
)

from hvac.v1 import Client

from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logger = logging.getLogger(__name__)


class TestProcessInfo:
    name: str
    process: subprocess.Popen
    extra: t.List[str]

    def __init__(
        self, name: str, process: subprocess.Popen, *extra: t.List[str]
    ) -> None:
        self.name = name
        self.process = process
        self.extra = extra

    def log_name(self, index: int, *suffixes: t.List[str], ext: str = ".log"):
        segmented = "_".join([self.name, str(index), *self.extra, *suffixes])
        return f"{segmented}{ext}"


class ServerManager:
    """Runs vault process running with test configuration and associates a hvac Client instance with this process."""

    active_config_paths: t.Optional[t.List[str]]
    config_paths: t.List[str]
    client: t.Optional[Client]
    use_consul: bool
    patch_config: bool

    def __init__(
        self,
        config_paths: t.List[str],
        client: Client = None,
        use_consul: bool = False,
        patch_config: bool = True,
    ):
        """Set up class attributes for managing a vault server process.

        :param config_paths: Full path to the Vault config to use when launching `vault server`.
        :type config_paths: list[str]
        :param client: Hvac Client that is used to initialize the vault server process.
        :type client: hvac.v1.Client
        """

        self.active_config_paths = None
        self.config_paths = config_paths
        self.client = client
        self.use_consul = use_consul
        self.patch_config = patch_config

        self.keys = None
        self.root_token = None

        self._processes: t.List[TestProcessInfo] = []

    def patch_config_port(
        self,
        config_file: str,
        *,
        port_getter: PortGetter.PortGetterProtocol,
        insert: bool = False,
        address: str = None,
        additional_sections: t.Optional[t.Dict[str, t.Any]] = None,
        output_dir: str = "generated",
    ):
        worker = os.getenv("PYTEST_XDIST_WORKER", "solo")
        config_parent = os.path.dirname(config_file)
        if not os.path.isabs(output_dir):
            output_dir = os.path.join(config_parent, output_dir)
        output_file = os.path.join(
            output_dir, os.path.basename(config_file).replace(".hcl", f"_{worker}.json")
        )

        with open(config_file, "r") as f:
            config: dict = hcl.load(f)

        if "listener" in config:
            listeners = config["listener"]
            if not isinstance(listeners, list):
                listeners = [listeners]
            for linstances in listeners:
                if "tcp" in linstances:
                    listener = linstances["tcp"]
                    if "address" in listener:
                        addr, port = listener["address"].split(":")
                        if address is not None:
                            addr = address
                        addr, port = port_getter(address=addr, port=int(port))
                        listener["address"] = ":".join((addr, str(port)))
                    elif insert:
                        addr, port = port_getter(address=address)
                        listener["address"] = ":".join((addr, str(port)))

        if additional_sections is not None:
            config.update(additional_sections)

        with open(output_file, "w") as f:
            hcl.api.json.dump(config, f, indent=4)

        return output_file

    def start(self):
        consul_config = None
        if self.use_consul:
            consul_addr = self.start_consul()
            consul_config = {
                "storage": {
                    "consul": {
                        "address": consul_addr,
                        "path": "vault_whatever/",
                    }
                }
            }
        self.start_vault(consul_config=consul_config)

    def start_vault(
        self, *, consul_config: dict = None, attempt=1, max_attempts=3, delay_s=1
    ):
        """Launch the vault server process and wait until its online and ready."""
        if shutil.which("vault") is None:
            raise SkipTest("Vault executable not found")

        with PortGetter() as g:
            self.active_config_paths = [
                self.patch_config_port(
                    config_path,
                    port_getter=g.get_port,
                    insert=True,
                    additional_sections=consul_config,
                )
                if self.patch_config
                else config_path
                for config_path in self.config_paths
            ]

        cluster_ready = False
        for config_path in self.active_config_paths:
            this_addr = self.get_config_vault_address(config_path)
            this_client = create_client(url=this_addr)
            if self.client is None:
                self.client = this_client

            command = ["vault", "server", "-config=" + config_path]
            logger.debug(f"Starting vault server with command: {command}")
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            self._processes.append(
                TestProcessInfo("vault", process, os.path.basename(config_path))
            )
            logger.debug(f"Spawned vault server with PID {process.pid}")

            attempts_left = 20
            last_exception = None
            while attempts_left > 0 and not cluster_ready:
                try:
                    logger.debug("Checking if vault is ready...")
                    this_client.sys.is_initialized()
                    cluster_ready = True
                    break
                except Exception as ex:
                    if process.poll() is not None:
                        stdout, stderr = process.stdout, process.stderr
                        if attempt < max_attempts:
                            logger.debug(
                                f"Starting Vault failed (attempt {attempt} of {max_attempts}):\n{last_exception}\n{stdout.readlines()}\n{stderr.readlines()}"
                            )
                            time.sleep(delay_s)
                            self.start_vault(
                                attempt=(attempt + 1),
                                max_attempts=max_attempts,
                                delay_s=delay_s,
                            )
                        else:
                            raise Exception(
                                "Vault server terminated before becoming ready"
                            )
                    logger.debug("Waiting for Vault to start")
                    time.sleep(0.5)
                    attempts_left -= 1
                    last_exception = ex
            if not cluster_ready:
                if process.poll() is None:
                    process.kill()
                stdout, stderr = process.communicate()
                if attempt < max_attempts:
                    logger.debug(
                        f"Vault never became ready (attempt {attempt} of {max_attempts}):\n{last_exception}\n{stdout}\n{stderr}"
                    )
                    time.sleep(delay_s)
                    self.start_vault(
                        attempt=(attempt + 1),
                        max_attempts=max_attempts,
                        delay_s=delay_s,
                    )
                else:
                    raise Exception(
                        "Unable to start Vault in background:\n{err}\n{stdout}\n{stderr}".format(
                            err=last_exception,
                            stdout=stdout,
                            stderr=stderr,
                        )
                    )

    def start_consul(
        self,
    ) -> str:
        if shutil.which("consul") is None:
            raise SkipTest("Consul executable not found")

        with PortGetter() as g:
            http_addr, http_port = g.get_port()
            _, server_port = g.get_port(address=http_addr)
            _, serf_lan_port = g.get_port(address=http_addr)
            _, serf_wan_port = g.get_port(address=http_addr)
            consul_addr = f"{http_addr}:{http_port}"
            command = [
                "consul",
                "agent",
                "-dev",
                "-disable-host-node-id",
                f"-serf-lan-port={serf_lan_port}",
                f"-serf-wan-port={serf_wan_port}",
                f"-server-port={server_port}",
                "-grpc-port=-1",
                "-grpc-tls-port=-1",
                f"-bind={http_addr}",
                f"-http-port={http_port}",
                "-dns-port=-1",
            ]

        logger.debug(f"Starting consul service with command: {command}")
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self._processes.append(
            TestProcessInfo("consul", process, os.getenv("PYTEST_XDIST_WORKER", "solo"))
        )
        attempts_left = 20
        last_exception = None
        while attempts_left > 0:
            try:
                catalog_nodes_response = requests.get(
                    f"http://{consul_addr}/v1/catalog/nodes"
                )
                nodes_list = catalog_nodes_response.json()
                logger.debug(
                    "JSON response from request to consul/v1/catalog/nodes: {resp}".format(
                        resp=nodes_list
                    )
                )
                node_name = nodes_list[0]["Node"]
                logger.debug(f"Current consul node name: {node_name}")
                node_health_response = requests.get(
                    f"http://{consul_addr}/v1/health/node/{node_name}"
                )
                node_health = node_health_response.json()
                logger.debug(f"Node health response: {node_health}")
                assert (
                    node_health[0]["Status"] == "passing"
                ), f'Node {node_name} status != "passing"'
                return consul_addr
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
        self.client = None
        for process_num, pinfo in reversed(list(enumerate(self._processes))):
            logger.debug(
                f"Terminating {pinfo.name} server with PID {pinfo.process.pid}"
            )
            if pinfo.process.poll() is None:
                pinfo.process.kill()

            if os.getenv("HVAC_OUTPUT_VAULT_STDERR", False):
                try:
                    stdout_lines, stderr_lines = pinfo.process.communicate()
                except ValueError:
                    pass
                else:
                    log_dir = get_config_file_path("generated", "logs")
                    try:
                        os.mkdir(log_dir)
                    except FileExistsError:
                        pass
                    stderr_filename = pinfo.log_name(process_num, "stderr")
                    stderr_path = get_config_file_path(log_dir, stderr_filename)
                    with open(stderr_path, "w") as f:
                        logger.debug(stderr_lines.decode())
                        f.writelines(stderr_lines.decode())
                    stdout_filename = pinfo.log_name(process_num, "stdout")
                    stdout_path = get_config_file_path(log_dir, stdout_filename)
                    with open(get_config_file_path(stdout_path), "w") as f:
                        logger.debug(stdout_lines.decode())
                        f.writelines(stdout_lines.decode())

    def initialize(self):
        """Perform initialization of the vault server process and record the provided unseal keys and root token."""
        if self.client.sys.is_initialized():
            raise RuntimeError(
                f"Vault is already initialized: {self.get_active_vault_addresses()}"
            )

        result = self.client.sys.initialize(secret_shares=5, secret_threshold=3)

        self.root_token = self.client.token = result["root_token"]
        self.keys = result["keys"]

    def restart_vault_cluster(self, perform_init=True):
        self.stop()
        self.start()
        if perform_init:
            self.initialize()

    def get_config_vault_address(self, config_path: str) -> str:
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
        return vault_address

    def get_active_vault_addresses(self):
        vault_addresses = []
        config_paths = (
            self.active_config_paths
            if self.active_config_paths is not None
            else self.config_paths
        )
        for config_path in config_paths:
            vault_addresses.append(self.get_config_vault_address(config_path))
        return vault_addresses

    def unseal(self):
        """Unseal the vault server process."""
        vault_addresses = self.get_active_vault_addresses()
        for vault_address in vault_addresses:
            # At this point, the vault server may not be ready yet, resulting in "Connection refused"
            # failures for requests. Let's retry multiple times before giving up.
            adapter = HTTPAdapter(
                max_retries=Retry(total=3, connect=3, backoff_factor=0.1)
            )
            session = requests.Session()
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            client = create_client(url=vault_address, session=session)
            client.sys.submit_unseal_keys(self.keys)

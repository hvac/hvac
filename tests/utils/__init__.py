"""Collection of classes and methods used by various hvac test cases."""
import base64
import logging
import operator
import os
import re
import socket
import subprocess
import sys
import time
from distutils.version import StrictVersion

from hvac import Client

logger = logging.getLogger(__name__)

VERSION_REGEX = re.compile(r'Vault v([0-9.]+)')
LATEST_VAULT_VERSION = '0.11.4'


def get_installed_vault_version():
    command = ['vault', '-version']
    process = subprocess.Popen(**get_popen_kwargs(args=command, stdout=subprocess.PIPE))
    output, _ = process.communicate()
    version = output.strip().split()[1].lstrip('v')
    # replace any '-beta1' type substrings with a StrictVersion parsable version. E.g., 1.0.0-beta1 => 1.0.0b1
    version = version.replace('-', '').replace('beta', 'b')
    return version


def skip_if_vault_version(supported_version, comparison=operator.lt):
    current_version = os.getenv('HVAC_VAULT_VERSION')
    if current_version is None or current_version.lower() == 'head':
        current_version = get_installed_vault_version()

    return comparison(StrictVersion(current_version), StrictVersion(supported_version))


def skip_if_vault_version_lt(supported_version):
    return skip_if_vault_version(supported_version, comparison=operator.lt)


def skip_if_vault_version_ge(supported_version):
    return skip_if_vault_version(supported_version, comparison=operator.ge)


def create_client(**kwargs):
    """Small helper to instantiate a :py:class:`hvac.v1.Client` class with the appropriate parameters for the test env.

    :param kwargs: Dictionary of additional keyword arguments to pass through to the Client instance being created.
    :type kwargs: dict
    :return: Instantiated :py:class:`hvac.v1.Client` class.
    :rtype: hvac.v1.Client
    """
    client_cert_path = get_config_file_path('client-cert.pem')
    client_key_path = get_config_file_path('client-key.pem')
    server_cert_path = get_config_file_path('server-cert.pem')

    return Client(
        url='https://localhost:8200',
        cert=(client_cert_path, client_key_path),
        verify=server_cert_path,
        **kwargs
    )


def get_free_port():
    """Small helper method used to discover an open port to use by mock API HTTP servers.

    :return: An available port number.
    :rtype: int
    """
    s = socket.socket(socket.AF_INET, type=socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    address, port = s.getsockname()
    s.close()
    return port


def load_config_file(filename):
    """Load test config file data for use by various test cases.

    :param filename: Name of the test data file.
    :type filename: str | unicode
    :return: Test data contents
    :rtype: str | unicode
    """
    test_data_path = get_config_file_path(filename)
    with open(test_data_path, 'r') as f:
        test_data = f.read()
    return test_data


def get_config_file_path(filename):
    """Get the path to a config file under the "tests/config_files" directory.

     I.e., the directory containing self-signed certificates, configuration files, etc. that are used for various tests.

    :param filename: Name of the test data file.
    :type filename: str | unicode
    :return: The absolute path to the test data directory.
    :rtype: str | unicode
    """
    # Use __file__ to derive a path relative to this module's location which points to the tests data directory.
    relative_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'config_files')
    return os.path.join(os.path.abspath(relative_path), filename)


def decode_generated_root_token(encoded_token, otp):
    """Decode a newly generated root token via Vault CLI.

    :param encoded_token: The token to decode.
    :type encoded_token: str | unicode
    :param otp: OTP code to use when decoding the token.
    :type otp: str | unicode
    :return: The decoded root token.
    :rtype: str | unicode
    """
    command = ['vault']
    if skip_if_vault_version_ge('0.9.6'):
        # before Vault ~0.9.6, the generate-root command was the first positional argument
        # afterwards, it was moved under the "operator" category
        command.append('operator')

    command.extend(
        [
            'generate-root',
            '-address', 'https://127.0.0.1:8200',
            '-tls-skip-verify',
            '-decode', encoded_token,
            '-otp', otp,
        ]
    )
    process = subprocess.Popen(**get_popen_kwargs(
        args=command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    ))

    stdout, stderr = process.communicate()
    logging.debug('decode_generated_root_token stdout: "%s"' % str(stdout))
    if stderr != '':
        logging.error('decode_generated_root_token stderr: %s' % stderr)

    new_token = stdout.replace('Root token:', '')
    new_token = new_token.strip()
    return new_token


def get_popen_kwargs(**popen_kwargs):
    """Helper method to add `encoding='utf-8'` to subprocess.Popen when we're in Python 3.x.

    :param popen_kwargs: List of keyword arguments to conditionally mutate
    :type popen_kwargs: **kwargs
    :return: Conditionally updated list of keyword arguments
    :rtype: dict
    """
    if sys.version_info[0] >= 3:
        popen_kwargs['encoding'] = 'utf-8'
    return popen_kwargs


def base64ify(bytes_or_str):
    """Helper method to perform base64 encoding across Python 2.7 and Python 3.X

    :param bytes_or_str:
    :type bytes_or_str:
    :return:
    :rtype:
    """
    if sys.version_info[0] >= 3 and isinstance(bytes_or_str, str):
        input_bytes = bytes_or_str.encode('utf8')
    else:
        input_bytes = bytes_or_str

    output_bytes = base64.urlsafe_b64encode(input_bytes)
    if sys.version_info[0] >= 3:
        return output_bytes.decode('ascii')
    else:
        return output_bytes


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

"""Collection of methods used by various hvac test cases."""
import base64
import json
import logging
import operator
import os
import re
import socket
import subprocess
from distutils.spawn import find_executable
from unittest import SkipTest, mock

from hvac import Client
from packaging.version import Version

logger = logging.getLogger(__name__)

VERSION_REGEX = re.compile(r"Vault v([0-9.]+)")
LATEST_VAULT_VERSION = "1.1.3"


def get_vault_version_string():
    if "cache" in get_vault_version_string.__dict__:
        return get_vault_version_string.cache
    if not find_executable("vault"):
        raise SkipTest("Vault executable not found")
    command = ["vault", "-version"]
    process = subprocess.Popen(**get_popen_kwargs(args=command, stdout=subprocess.PIPE))
    output, _ = process.communicate()
    version_string = output.strip().split()[1].lstrip("v")
    get_vault_version_string.cache = version_string
    return version_string


def get_installed_vault_version():
    version_string = get_vault_version_string()
    # replace any '-beta1' type substrings with a StrictVersion parsable version. E.g., 1.0.0-beta1 => 1.0.0b1
    version = version_string.replace("-", "").replace("beta", "b")
    version = version.replace("+ent", "")
    return version


def is_enterprise():
    version_string = get_vault_version_string()
    if re.search(r"\+ent$", version_string) is not None:
        return True
    return False


def if_vault_version(supported_version, comparison=operator.lt):
    current_version = get_installed_vault_version()
    return comparison(Version(current_version), Version(supported_version))


def vault_version_lt(supported_version):
    return if_vault_version(supported_version, comparison=operator.lt)


def vault_version_ge(supported_version):
    return if_vault_version(supported_version, comparison=operator.ge)


def vault_version_eq(supported_version):
    return if_vault_version(supported_version, comparison=operator.eq)


def get_generate_root_otp():
    """Get a appropriate OTP for the current Vault version under test.

    :return: OTP to use in generate root operations
    :rtype: str
    """
    if vault_version_ge("1.10.0"):
        test_otp = "BMjzW3wAsEzINXCM05Wbas3u9zSl"
    elif vault_version_ge("1.0.0"):
        test_otp = "ygs0vL8GIxu0AjRVEmJ5jLCVq8"
    else:
        test_otp = "RSMGkAqBH5WnVLrDTbZ+UQ=="
    return test_otp


def create_client(url="https://localhost:8200", use_env=False, **kwargs):
    """Small helper to instantiate a :py:class:`hvac.v1.Client` class with the appropriate parameters for the test env.

    :param url: Vault address to configure the client with.
    :type url: str
    :param use_env: configure vault using environment variable
    :type use_env: bool
    :param kwargs: Dictionary of additional keyword arguments to pass through to the Client instance being created.
    :type kwargs: dict
    :return: Instantiated :py:class:`hvac.v1.Client` class.
    :rtype: hvac.v1.Client
    """

    client_cert_path = get_config_file_path("client-cert.pem")
    client_key_path = get_config_file_path("client-key.pem")
    server_cert_path = get_config_file_path("server-cert.pem")
    if use_env:
        with mock.patch("hvac.v1.VAULT_CAPATH", server_cert_path):
            with mock.patch("hvac.v1.VAULT_CLIENT_CERT", client_cert_path):
                with mock.patch("hvac.v1.VAULT_CLIENT_KEY", client_key_path):
                    client = Client(
                        url=url,
                        **kwargs,
                    )
    else:
        client = Client(
            url=url,
            cert=(client_cert_path, client_key_path),
            verify=server_cert_path,
            **kwargs,
        )
    return client


def get_free_port():
    """Small helper method used to discover an open port to use by mock API HTTP servers.

    :return: An available port number.
    :rtype: int
    """
    s = socket.socket(socket.AF_INET, type=socket.SOCK_STREAM)
    s.bind(("localhost", 0))
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
    with open(test_data_path) as f:
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
    relative_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "config_files"
    )
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
    command = ["vault"]
    if vault_version_ge("0.9.6"):
        # before Vault ~0.9.6, the generate-root command was the first positional argument
        # afterwards, it was moved under the "operator" category
        command.append("operator")

    command.extend(
        [
            "generate-root",
            "-address",
            "https://127.0.0.1:8200",
            "-tls-skip-verify",
            "-decode",
            encoded_token,
            "-otp",
            otp,
        ]
    )
    process = subprocess.Popen(
        **get_popen_kwargs(args=command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    )

    stdout, stderr = process.communicate()
    logging.debug('decode_generated_root_token stdout: "%s"' % str(stdout))
    if stderr != "":
        logging.error("decode_generated_root_token stderr: %s" % stderr)

    try:
        # On the off chance VAULT_FORMAT=json or such is set in the test environment:
        new_token = json.loads(stdout)["token"]
    except ValueError:
        new_token = stdout.replace("Root token:", "")
    new_token = new_token.strip()
    return new_token


def get_popen_kwargs(**popen_kwargs):
    """Helper method to add `encoding='utf-8'` to subprocess.Popen.

    :param popen_kwargs: List of keyword arguments to conditionally mutate
    :type popen_kwargs: **kwargs
    :return: Conditionally updated list of keyword arguments
    :rtype: dict
    """
    popen_kwargs["encoding"] = "utf-8"
    return popen_kwargs


def base64ify(bytes_or_str):
    """Helper method to perform base64 encoding

    :param bytes_or_str:
    :type bytes_or_str:
    :return:
    :rtype:
    """
    if isinstance(bytes_or_str, str):
        input_bytes = bytes_or_str.encode("utf8")
    else:
        input_bytes = bytes_or_str

    output_bytes = base64.urlsafe_b64encode(input_bytes)
    return output_bytes.decode("ascii")


def configure_pki(
    client, common_name="hvac.com", role_name="my-role", mount_point="pki"
):
    """Helper function to configure a pki backend for integration tests that need to work with lease IDs.

    :param client: Authenticated hvac Client instance.
    :typeclient: hvac.Client
    :param common_name: Common name to configure in the pki backend
    :type common_name: str
    :param role_name: Name of the test role to configure.
    :type role_name: str
    :param mount_point: The path the pki backend is mounted under.
    :type mount_point: str
    :return: Nothing.
    :rtype: None.
    """
    if f"{mount_point}/" in client.sys.list_mounted_secrets_engines():
        client.sys.disable_secrets_engine(mount_point)

    client.sys.enable_secrets_engine(backend_type="pki", path=mount_point)

    client.write_data(
        path=f"{mount_point}/root/generate/internal",
        data=dict(
            common_name=common_name,
            ttl="8760h",
        ),
    )
    client.write_data(
        path=f"{mount_point}/config/urls",
        data=dict(
            issuing_certificates="http://127.0.0.1:8200/v1/pki/ca",
            crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl",
        ),
    )
    client.write_data(
        path=f"{mount_point}/roles/{role_name}",
        data=dict(
            allowed_domains=common_name,
            allow_subdomains=True,
            generate_lease=True,
            max_ttl="72h",
        ),
    )


def disable_pki(client, mount_point="pki"):
    """Disable a previously configured pki backend.

    :param client: Authenticated hvac Client instance.
    :typeclient: hvac.Client
    :param mount_point: The path the pki backend is mounted under.
    :type mount_point: str
    """
    client.sys.disable_secrets_engine(mount_point)

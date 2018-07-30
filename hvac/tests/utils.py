import re
import subprocess
import time

from semantic_version import Spec, Version


class ServerManager(object):
    def __init__(self, config_path, client):
        self.config_path = config_path
        self.client = client

        self.keys = None
        self.root_token = None

        self._process = None

    def start(self):
        command = ['vault', 'server', '-config=' + self.config_path]

        self._process = subprocess.Popen(command,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)

        attempts_left = 20
        last_exception = None
        while attempts_left > 0:
            try:
                self.client.is_initialized()
                return
            except Exception as ex:
                print('Waiting for Vault to start')

                time.sleep(0.5)

                attempts_left -= 1
                last_exception = ex

        raise Exception('Unable to start Vault in background: {0}'.format(last_exception))

    def stop(self):
        self._process.kill()

    def initialize(self):
        assert not self.client.is_initialized()

        result = self.client.initialize()

        self.root_token = result['root_token']
        self.keys = result['keys']

    def unseal(self):
        self.client.unseal_multi(self.keys)


VERSION_REGEX = re.compile('Vault v([\d\.]+)')


def match_version(spec):
    output = subprocess.check_output(['vault', 'version']).decode('ascii')
    version = Version(VERSION_REGEX.match(output).group(1))

    return Spec(spec).match(version)


def configure_test_pki(client, common_name='hvac.com', role_name='my-role', mount_point='pki'):
    """Helper function to configure a pki backend for integration tests that need to work with lease IDs.

    :param client: Authenticated hvac.v1.Client instance.
    :type client: hvac.v1.Client
    :param common_name: Common name to configure in the pki backend
    :type common_name: str.
    :param role_name: Name of the test role to configure.
    :type role_name: str.
    :param mount_point: The path the pki backend is mounted under.
    :type mount_point: str.
    :return: Nothing.
    :rtype: None.
    """
    if '{path}/'.format(path=mount_point) in client.list_secret_backends():
        client.disable_secret_backend(mount_point)

    client.enable_secret_backend(backend_type='pki', mount_point=mount_point)

    client.write(
        path='{path}/root/generate/internal'.format(path=mount_point),
        common_name=common_name,
        ttl='8760h',
    )
    client.write(
        path='{path}/config/urls'.format(path=mount_point),
        issuing_certificates="http://127.0.0.1:8200/v1/pki/ca",
        crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl",
    )
    client.write(
        path='{path}/roles/{name}'.format(path=mount_point, name=role_name),
        allowed_domains=common_name,
        allow_subdomains=True,
        generate_lease=True,
        max_ttl='72h',
    )


def disable_test_pki(client, mount_point='pki'):
    """

    :param client: Authenticated hvac.v1.Client instance.
    :type client: hvac.v1.Client
    :param mount_point: The path the pki backend is mounted under.
    :type mount_point: str.
    :return: Nothing.
    :rtype: None.
    """

    # Reset integration test state
    client.disable_secret_backend(mount_point)

import logging
import os
import re
import subprocess
import time

from semantic_version import Spec, Version

from hvac import Client

logger = logging.getLogger(__name__)


VERSION_REGEX = re.compile('Vault v([\d\.]+)')

# Use __file__ to derive an absolute path relative to this modules location to point to the test data directory.
TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'test')


def create_client(**kwargs):
    client_cert_path = os.path.join(TEST_DATA_DIR, 'client-cert.pem')
    client_key_path = os.path.join(TEST_DATA_DIR, 'client-key.pem')
    server_cert_path = os.path.join(TEST_DATA_DIR, 'server-cert.pem')

    return Client(
        url='https://localhost:8200',
        cert=(client_cert_path, client_key_path),
        verify=server_cert_path,
        timeout=2,
        **kwargs
    )


def match_version(spec):
    output = subprocess.check_output(['vault', 'version']).decode('ascii')
    version = Version(VERSION_REGEX.match(output).group(1))

    return Spec(spec).match(version)


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
                logger.debug('Waiting for Vault to start')

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


class HvacIntegrationTestCase(object):
    manager = None
    client = None

    @classmethod
    def setUpClass(cls):
        cls.manager = ServerManager(
            config_path=os.path.join(TEST_DATA_DIR, 'vault-tls.hcl'),
            client=create_client()
        )
        cls.manager.start()
        cls.manager.initialize()
        cls.manager.unseal()

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop()

    def setUp(self):
        self.client = create_client(token=self.manager.root_token)

    def tearDown(self):
        self.client.token = self.manager.root_token

    def prep_policy(self, name):
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

    def configure_test_pki(self, common_name='hvac.com', role_name='my-role', mount_point='pki'):
        """Helper function to configure a pki backend for integration tests that need to work with lease IDs.

        :param common_name: Common name to configure in the pki backend
        :type common_name: str.
        :param role_name: Name of the test role to configure.
        :type role_name: str.
        :param mount_point: The path the pki backend is mounted under.
        :type mount_point: str.
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

    def disable_test_pki(self, mount_point='pki'):
        """

        :param mount_point: The path the pki backend is mounted under.
        :type mount_point: str.
        :return: Nothing.
        :rtype: None.
        """

        # Reset integration test state
        self.client.disable_secret_backend(mount_point)

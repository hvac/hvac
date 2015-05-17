import subprocess
import time
from unittest import TestCase

import requests
from nose.tools import *

from vault import Client, exceptions

class IntegrationTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.process = cls.start_background()
        cls.initialize_vault()

    @classmethod
    def start_background(cls):
        command = ["vault", "server", "-config=vault.hcl"]

        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        while True:
            try:
                requests.get('http://localhost:8200/v1/sys/init').raise_for_status()
                return process
            except:
                print("Waiting for Vault to start")
                time.sleep(0.1)

    @classmethod
    def initialize_vault(cls):
        client = Client()

        result = client.initialize()

        token = result['root_token']
        keys = result['keys']

        for key in keys[0:3]:
            client.unseal(5, key)

        cls.token = token

    @classmethod
    def tearDownClass(cls):
        cls.process.kill()

    def setUp(self):
        cls = type(self)

        self.client = Client()
        self.client.auth_token(cls.token)

    def test_generic_secret_backend(self):
        self.client.write('secret/foo', zap='zip')
        result = self.client.read('secret/foo')

        assert result['data']['zap'] == 'zip'

        self.client.delete('secret/foo')

    def test_auth_backend_manipulation(self):
        assert 'github/' not in self.client.list_auth_backends()

        self.client.enable_auth_backend('github')
        assert 'github/' in self.client.list_auth_backends()

        self.client.disable_auth_backend('github')
        assert 'github/' not in self.client.list_auth_backends()

    def test_auth_token_manipulation(self):
        result = self.client.create_token(lease='1h')
        assert result['auth']['client_token']

        lookup = self.client.lookup_token(result['auth']['client_token'])
        assert result['auth']['client_token'] == lookup['data']['id']

        renew = self.client.renew_token(lookup['data']['id'])
        assert result['auth']['client_token'] == renew['auth']['client_token']

        self.client.revoke_token(lookup['data']['id'])

        try:
            lookup = self.client.lookup_token(result['auth']['client_token'])
            assert False
        except exceptions.InvalidPath:
            assert True

    def test_userpass_auth(self):
        self.client.enable_auth_backend('userpass')

        self.client.write('auth/userpass/users/testuser', password='testpass', policies='root')

        result = self.client.auth_userpass('testuser', 'testpass')

    def test_app_id_auth(self):
        self.client.enable_auth_backend('app-id')

        self.client.write('auth/app-id/map/app-id/foo', value='root')
        self.client.write('auth/app-id/map/user-id/bar', value='foo')

        result = self.client.auth_app_id('foo', 'bar')

    @raises(exceptions.InvalidPath)
    def test_invalid_path(self):
        self.client.read('secret/I/do/not/exist')

    @raises(exceptions.InternalServerError)
    def test_internal_server_error(self):
        self.client.read('handler/does/not/exist')

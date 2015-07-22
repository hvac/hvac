from unittest import TestCase, skipIf

from nose.tools import *
import requests

from hvac import Client, exceptions
from hvac.tests import util

def create_client(**kwargs):
    return Client(**kwargs)

class IntegrationTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manager = util.ServerManager(config_path='test/vault.hcl', client=create_client())
        cls.manager.start()
        cls.manager.initialize()
        cls.manager.unseal()

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop()

    def setUp(self):
        cls = type(self)

        self.client = create_client(token=cls.manager.root_token)

    def test_unseal_multi(self):
        cls = type(self)

        self.client.seal()

        keys = cls.manager.keys

        result = self.client.unseal_multi(keys[0:2])

        assert result['sealed']
        assert result['progress'] == 2

        result = self.client.unseal_multi(keys[2:3])

        assert not result['sealed']

    def test_seal_unseal(self):
        cls = type(self)

        assert not self.client.is_sealed()

        self.client.seal()

        assert self.client.is_sealed()

        cls.manager.unseal()

        assert not self.client.is_sealed()

    def test_ha_status(self):
        assert 'ha_enabled' in self.client.ha_status

    def test_generic_secret_backend(self):
        self.client.write('secret/foo', zap='zip')
        result = self.client.read('secret/foo')

        assert result['data']['zap'] == 'zip'

        self.client.delete('secret/foo')

    def test_write_with_response(self):
        self.client.enable_secret_backend('transit')

        plaintext = 'test'

        self.client.write('transit/keys/foo')

        result = self.client.write('transit/encrypt/foo', plaintext=plaintext)
        ciphertext = result['data']['ciphertext']

        result = self.client.write('transit/decrypt/foo', ciphertext=ciphertext)
        assert result['data']['plaintext'] == plaintext

    def test_read_nonexistent_key(self):
        assert not self.client.read('secret/I/dont/exist')

    def test_auth_backend_manipulation(self):
        assert 'github/' not in self.client.list_auth_backends()

        self.client.enable_auth_backend('github')
        assert 'github/' in self.client.list_auth_backends()

        self.client.disable_auth_backend('github')
        assert 'github/' not in self.client.list_auth_backends()

    def test_secret_backend_manipulation(self):
        assert 'test/' not in self.client.list_secret_backends()

        self.client.enable_secret_backend('generic', mount_point='test')
        assert 'test/' in self.client.list_secret_backends()

        self.client.remount_secret_backend('test', 'foobar')
        assert 'test/' not in self.client.list_secret_backends()
        assert 'foobar/' in self.client.list_secret_backends()

        self.client.disable_secret_backend('foobar')
        assert 'foobar/' not in self.client.list_secret_backends()

    def test_audit_backend_manipulation(self):
        assert 'tmpfile/' not in self.client.list_audit_backends()

        options = {
            'path': '/tmp/vault.audit.log'
        }

        self.client.enable_audit_backend('file', options=options, name='tmpfile')
        assert 'tmpfile/' in self.client.list_audit_backends()

        self.client.disable_audit_backend('tmpfile')
        assert 'tmpfile/' not in self.client.list_audit_backends()

    def test_policy_manipulation(self):
        assert 'root' in self.client.list_policies()

        policy = """
        path "sys" {
          policy = "deny"
        }

        path "secret" {
          policy = "write"
        }
        """

        self.client.set_policy('test', policy)
        assert 'test' in self.client.list_policies()

        self.client.delete_policy('test')
        assert 'test' not in self.client.list_policies()

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
        except exceptions.Forbidden:
            assert True
        except exceptions.InvalidPath:
            assert True

    def test_userpass_auth(self):
        self.client.enable_auth_backend('userpass')

        self.client.write('auth/userpass/users/testuser', password='testpass', policies='root')

        result = self.client.auth_userpass('testuser', 'testpass')

        assert self.client.token == result['auth']['client_token']
        assert self.client.is_authenticated()

    def test_app_id_auth(self):
        self.client.enable_auth_backend('app-id')

        self.client.write('auth/app-id/map/app-id/foo', value='root')
        self.client.write('auth/app-id/map/user-id/bar', value='foo')

        result = self.client.auth_app_id('foo', 'bar')

        assert self.client.token == result['auth']['client_token']
        assert self.client.is_authenticated()

    def test_missing_token(self):
        client = create_client()
        assert not client.is_authenticated()

    def test_invalid_token(self):
        client = create_client(token='not-a-real-token')
        assert not client.is_authenticated()

    def test_client_authenticated(self):
        assert self.client.is_authenticated()

    def test_client_logout(self):
        self.client.logout()
        assert not self.client.is_authenticated()

    @skipIf(util.match_version('<0.2.0'), 'Rekey API added in 0.2.0')
    def test_rekey(self):
        cls = type(self)

        assert not self.client.rekey_status['started']

        self.client.start_rekey()
        assert self.client.rekey_status['started']

        self.client.cancel_rekey()
        assert not self.client.rekey_status['started']

        self.client.start_rekey()

        for key in cls.manager.keys:
            result = self.client.rekey(key)
            if result['complete']:
                cls.manager.keys = result['keys']
                assert not self.client.rekey_status['started']
                break

        cls.manager.unseal()

    @skipIf(util.match_version('<0.2.0'), 'Rotate API added in 0.2.0')
    def test_rotate(self):
        status = self.client.key_status

        self.client.rotate()

        assert self.client.key_status['term'] > status['term']

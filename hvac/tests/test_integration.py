from unittest import TestCase, skipIf

import hcl
import requests
from nose.tools import *
from time import sleep

from hvac import Client, exceptions
from hvac.tests import util


def create_client(**kwargs):
    return Client(url='https://localhost:8200',
                  cert=('test/client-cert.pem', 'test/client-key.pem'),
                  verify='test/server-cert.pem',
                  **kwargs)

class IntegrationTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manager = util.ServerManager(config_path='test/vault-tls.hcl', client=create_client())
        cls.manager.start()
        cls.manager.initialize()
        cls.manager.unseal()

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop()

    def root_token(self):
        cls = type(self)
        return cls.manager.root_token

    def setUp(self):
        self.client = create_client(token=self.root_token())

    def test_unseal_multi(self):
        cls = type(self)

        self.client.seal()

        keys = cls.manager.keys

        result = self.client.unseal_multi(keys[0:2])

        assert result['sealed']
        assert result['progress'] == 2

        result = self.client.unseal_reset()
        assert result['progress'] == 0
        result = self.client.unseal_multi(keys[1:3])
        assert result['sealed']
        assert result['progress'] == 2
        result = self.client.unseal_multi(keys[0:1])
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

    def test_list_directory(self):
        self.client.write('secret/test-list/bar/foo', value='bar')
        self.client.write('secret/test-list/foo', value='bar')
        result = self.client.list('secret/test-list')

        assert result['data']['keys'] == ['bar/', 'foo']

        self.client.delete('secret/test-list/bar/foo')
        self.client.delete('secret/test-list/foo')

    def test_write_with_response(self):
        self.client.enable_secret_backend('transit')

        plaintext = 'test'

        self.client.write('transit/keys/foo')

        result = self.client.write('transit/encrypt/foo', plaintext=plaintext)
        ciphertext = result['data']['ciphertext']

        result = self.client.write('transit/decrypt/foo', ciphertext=ciphertext)
        assert result['data']['plaintext'] == plaintext

    def test_wrap_write(self):
        if 'approle/' not in self.client.list_auth_backends():
            self.client.enable_auth_backend("approle")
 
        self.client.write("auth/approle/role/testrole")
        result = self.client.write('auth/approle/role/testrole/secret-id', wrap_ttl="10s")
        assert 'token' in result['wrap_info']
        self.client.unwrap(result['wrap_info']['token'])
        self.client.disable_auth_backend("approle")

    def test_read_nonexistent_key(self):
        assert not self.client.read('secret/I/dont/exist')

    def test_auth_backend_manipulation(self):
        assert 'github/' not in self.client.list_auth_backends()

        self.client.enable_auth_backend('github')
        assert 'github/' in self.client.list_auth_backends()

        self.client.token = self.root_token()
        self.client.disable_auth_backend('github')
        assert 'github/' not in self.client.list_auth_backends()

    def test_secret_backend_manipulation(self):
        assert 'test/' not in self.client.list_secret_backends()

        self.client.enable_secret_backend('generic', mount_point='test')
        assert 'test/' in self.client.list_secret_backends()

        self.client.tune_secret_backend('generic', mount_point='test', default_lease_ttl='3600s', max_lease_ttl='8600s')
        assert 'max_lease_ttl' in self.client.get_secret_backend_tuning('generic', mount_point='test')
        assert 'default_lease_ttl' in self.client.get_secret_backend_tuning('generic', mount_point='test')

        self.client.remount_secret_backend('test', 'foobar')
        assert 'test/' not in self.client.list_secret_backends()
        assert 'foobar/' in self.client.list_secret_backends()

        self.client.token = self.root_token()
        self.client.disable_secret_backend('foobar')
        assert 'foobar/' not in self.client.list_secret_backends()

    def test_audit_backend_manipulation(self):
        assert 'tmpfile/' not in self.client.list_audit_backends()

        options = {
            'path': '/tmp/vault.audit.log'
        }

        self.client.enable_audit_backend('file', options=options, name='tmpfile')
        assert 'tmpfile/' in self.client.list_audit_backends()

        self.client.token = self.root_token()
        self.client.disable_audit_backend('tmpfile')
        assert 'tmpfile/' not in self.client.list_audit_backends()

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

    def test_policy_manipulation(self):
        assert 'root' in self.client.list_policies()
        assert self.client.get_policy('test') is None
        policy, parsed_policy = self.prep_policy('test')
        assert 'test' in self.client.list_policies()
        assert policy == self.client.get_policy('test')
        assert parsed_policy == self.client.get_policy('test', parse=True)

        self.client.delete_policy('test')
        assert 'test' not in self.client.list_policies()

    def test_json_policy_manipulation(self):
        assert 'root' in self.client.list_policies()

        policy = {
            "path": {
                "sys": {
                    "policy": "deny"
                },
                "secret": {
                    "policy": "write"
                }
            }
        }

        self.client.set_policy('test', policy)
        assert 'test' in self.client.list_policies()

        self.client.delete_policy('test')
        assert 'test' not in self.client.list_policies()

    def test_auth_token_manipulation(self):
        result = self.client.create_token(lease='1h', renewable=True)
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
        except exceptions.InvalidRequest:
            assert True

    def test_userpass_auth(self):
        if 'userpass/' in self.client.list_auth_backends():
            self.client.disable_auth_backend('userpass')

        self.client.enable_auth_backend('userpass')

        self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        result = self.client.auth_userpass('testuser', 'testpass')

        assert self.client.token == result['auth']['client_token']
        assert self.client.is_authenticated()

        self.client.token = self.root_token()
        self.client.disable_auth_backend('userpass')

    def test_create_userpass(self):
        if 'userpass/' not in self.client.list_auth_backends():
            self.client.enable_auth_backend('userpass')

        self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert self.client.is_authenticated()

        # Test ttl:
        self.client.token = self.root_token()
        self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root', ttl='10s')
        self.client.token = result['auth']['client_token']

        result = self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert result['auth']['lease_duration'] == 10

        self.client.token = self.root_token()
        self.client.disable_auth_backend('userpass')

    def test_delete_userpass(self):
        if 'userpass/' not in self.client.list_auth_backends():
            self.client.enable_auth_backend('userpass')

        self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert self.client.is_authenticated()

        self.client.token = self.root_token()
        self.client.delete_userpass('testcreateuser')
        assert_raises(exceptions.InvalidRequest, self.client.auth_userpass, 'testcreateuser', 'testcreateuserpass')

    def test_app_id_auth(self):
        if 'app-id/' in self.client.list_auth_backends():
            self.client.disable_auth_backend('app-id')

        self.client.enable_auth_backend('app-id')

        self.client.write('auth/app-id/map/app-id/foo', value='not_root')
        self.client.write('auth/app-id/map/user-id/bar', value='foo')

        result = self.client.auth_app_id('foo', 'bar')

        assert self.client.token == result['auth']['client_token']
        assert self.client.is_authenticated()

        self.client.token = self.root_token()
        self.client.disable_auth_backend('app-id')

    def test_create_app_id(self):
        if 'app-id/' not in self.client.list_auth_backends():
            self.client.enable_auth_backend('app-id')

        self.client.create_app_id('testappid', policies='not_root', display_name='displayname')

        result = self.client.read('auth/app-id/map/app-id/testappid')
        lib_result = self.client.get_app_id('testappid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testappid'
        assert result['data']['display_name'] == 'displayname'
        assert result['data']['value'] == 'not_root'
        self.client.delete_app_id('testappid')
        assert self.client.get_app_id('testappid')['data'] is None

        self.client.token = self.root_token()
        self.client.disable_auth_backend('app-id')

    def test_create_user_id(self):
        if 'app-id/' not in self.client.list_auth_backends():
            self.client.enable_auth_backend('app-id')

        self.client.create_app_id('testappid', policies='not_root', display_name='displayname')
        self.client.create_user_id('testuserid', app_id='testappid')

        result = self.client.read('auth/app-id/map/user-id/testuserid')
        lib_result = self.client.get_user_id('testuserid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testuserid'
        assert result['data']['value'] == 'testappid'

        result = self.client.auth_app_id('testappid', 'testuserid')

        assert self.client.token == result['auth']['client_token']
        assert self.client.is_authenticated()
        self.client.token = self.root_token()
        self.client.delete_user_id('testuserid')
        assert self.client.get_user_id('testuserid')['data'] is None

        self.client.token = self.root_token()
        self.client.disable_auth_backend('app-id')

    def test_create_role(self):
        if 'approle/' in self.client.list_auth_backends():
            self.client.disable_auth_backend('approle')
        self.client.enable_auth_backend('approle')

        self.client.create_role('testrole')

        result = self.client.read('auth/approle/role/testrole')
        lib_result = self.client.get_role('testrole')
        del result['request_id']
        del lib_result['request_id']

        assert result == lib_result
        self.client.token = self.root_token()
        self.client.disable_auth_backend('approle')

    def test_create_delete_role_secret_id(self):
        if 'approle/' in self.client.list_auth_backends():
            self.client.disable_auth_backend('approle')
        self.client.enable_auth_backend('approle')

        self.client.create_role('testrole')
        create_result = self.client.create_role_secret_id('testrole', {'foo':'bar'})
        secret_id = create_result['data']['secret_id']
        result = self.client.get_role_secret_id('testrole', secret_id)
        assert result['data']['metadata']['foo'] == 'bar'
        self.client.delete_role_secret_id('testrole', secret_id)
        try:
            self.client.get_role_secret_id('testrole', secret_id)
            assert False
        except (exceptions.InvalidPath, ValueError):
            assert True
        self.client.token = self.root_token()
        self.client.disable_auth_backend('approle')

    def test_auth_approle(self):
        if 'approle/' in self.client.list_auth_backends():
            self.client.disable_auth_backend('approle')
        self.client.enable_auth_backend('approle')

        self.client.create_role('testrole')
        create_result = self.client.create_role_secret_id('testrole', {'foo':'bar'})
        secret_id = create_result['data']['secret_id']
        role_id = self.client.get_role_id('testrole')
        result = self.client.auth_approle(role_id, secret_id)
        assert result['auth']['metadata']['foo'] == 'bar'
        assert self.client.token == result['auth']['client_token']
        assert self.client.is_authenticated()
        self.client.token = self.root_token()
        self.client.disable_auth_backend('approle')

    def test_auth_approle_dont_use_token(self):
        if 'approle/' in self.client.list_auth_backends():
            self.client.disable_auth_backend('approle')
        self.client.enable_auth_backend('approle')

        self.client.create_role('testrole')
        create_result = self.client.create_role_secret_id('testrole', {'foo':'bar'})
        secret_id = create_result['data']['secret_id']
        role_id = self.client.get_role_id('testrole')
        result = self.client.auth_approle(role_id, secret_id, use_token=False)
        assert result['auth']['metadata']['foo'] == 'bar'
        assert self.client.token != result['auth']['client_token']
        self.client.token = self.root_token()
        self.client.disable_auth_backend('approle')

    def test_missing_token(self):
        client = create_client()
        assert not client.is_authenticated()

    def test_invalid_token(self):
        client = create_client(token='not-a-real-token')
        assert not client.is_authenticated()

    def test_illegal_token(self):
        client = create_client(token='token-with-new-line\n')
        try:
            client.is_authenticated()
        except ValueError as e:
            assert 'Invalid header value' in str(e)

    def test_broken_token(self):
        client = create_client(token='\x1b')
        try:
            client.is_authenticated()
        except exceptions.InvalidRequest as e:
            assert "invalid header value" in str(e)

    def test_client_authenticated(self):
        assert self.client.is_authenticated()

    def test_client_logout(self):
        self.client.logout()
        assert not self.client.is_authenticated()

    def test_revoke_self_token(self):
        if 'userpass/' in self.client.list_auth_backends():
            self.client.disable_auth_backend('userpass')

        self.client.enable_auth_backend('userpass')

        self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        result = self.client.auth_userpass('testuser', 'testpass')

        self.client.revoke_self_token()
        assert not self.client.is_authenticated()

    def test_rekey_multi(self):
        cls = type(self)

        assert not self.client.rekey_status['started']

        self.client.start_rekey()
        assert self.client.rekey_status['started']

        self.client.cancel_rekey()
        assert not self.client.rekey_status['started']

        result = self.client.start_rekey()

        keys = cls.manager.keys

        result = self.client.rekey_multi(keys, nonce=result['nonce'])
        assert result['complete']

        cls.manager.keys = result['keys']
        cls.manager.unseal()

    def test_rotate(self):
        status = self.client.key_status

        self.client.rotate()

        assert self.client.key_status['term'] > status['term']

    def test_tls_auth(self):
        self.client.enable_auth_backend('cert')

        with open('test/client-cert.pem') as fp:
            certificate = fp.read()

        self.client.write('auth/cert/certs/test', display_name='test',
                          policies='not_root', certificate=certificate)

        result = self.client.auth_tls()

    def test_gh51(self):
        key = 'secret/http://test.com'

        self.client.write(key, foo='bar')

        result = self.client.read(key)

        assert result['data']['foo'] == 'bar'

    def test_token_accessor(self):
        # Create token, check accessor is provided
        result = self.client.create_token(lease='1h')
        token_accessor = result['auth'].get('accessor', None)
        assert token_accessor

        # Look up token by accessor, make sure token is excluded from results
        lookup = self.client.lookup_token(token_accessor, accessor=True)
        assert lookup['data']['accessor'] == token_accessor
        assert not lookup['data']['id']

        # Revoke token using the accessor
        self.client.revoke_token(token_accessor, accessor=True)

        # Look up by accessor should fail
        with self.assertRaises(exceptions.InvalidRequest):
            lookup = self.client.lookup_token(token_accessor, accessor=True)

        # As should regular lookup
        with self.assertRaises(exceptions.Forbidden):
            lookup = self.client.lookup_token(result['auth']['client_token'])

    def test_wrapped_token_success(self):
        wrap = self.client.create_token(wrap_ttl='1m')

        # Unwrap token
        result = self.client.unwrap(wrap['wrap_info']['token'])
        assert result['auth']['client_token']

        # Validate token
        lookup = self.client.lookup_token(result['auth']['client_token'])
        assert result['auth']['client_token'] == lookup['data']['id']

    def test_wrapped_token_intercept(self):
        wrap = self.client.create_token(wrap_ttl='1m')

        # Intercept wrapped token
        _ = self.client.unwrap(wrap['wrap_info']['token'])

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.Forbidden):
            result = self.client.unwrap(wrap['wrap_info']['token'])

    def test_wrapped_token_cleanup(self):
        wrap = self.client.create_token(wrap_ttl='1m')

        _token = self.client.token
        _ = self.client.unwrap(wrap['wrap_info']['token'])
        assert self.client.token == _token

    def test_wrapped_token_revoke(self):
        wrap = self.client.create_token(wrap_ttl='1m')

        # Revoke token before it's unwrapped
        self.client.revoke_token(wrap['wrap_info']['wrapped_accessor'], accessor=True)

        # Unwrap token anyway
        result = self.client.unwrap(wrap['wrap_info']['token'])
        assert result['auth']['client_token']

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            lookup = self.client.lookup_token(result['auth']['client_token'])

    def test_create_token_explicit_max_ttl(self):

        token = self.client.create_token(ttl='30m', explicit_max_ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    def test_create_token_max_ttl(self):

        token = self.client.create_token(ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    def test_token_roles(self):
        # No roles, list_token_roles == None
        before = self.client.list_token_roles()
        assert not before

        # Create token role
        assert self.client.create_token_role('testrole').status_code == 204

        # List token roles
        during = self.client.list_token_roles()['data']['keys']
        assert len(during) == 1
        assert during[0] == 'testrole'

        # Delete token role
        self.client.delete_token_role('testrole')

        # No roles, list_token_roles == None
        after = self.client.list_token_roles()
        assert not after

    def test_create_token_w_role(self):
        # Create policy
        self.prep_policy('testpolicy')

        # Create token role w/ policy
        assert self.client.create_token_role('testrole',
                allowed_policies='testpolicy').status_code == 204

        # Create token against role
        token = self.client.create_token(lease='1h', role='testrole')
        assert token['auth']['client_token']
        assert token['auth']['policies'] == ['default', 'testpolicy']

        # Cleanup
        self.client.delete_token_role('testrole')
        self.client.delete_policy('testpolicy')

    def test_ec2_role_crud(self):
        if 'aws-ec2/' in self.client.list_auth_backends():
            self.client.disable_auth_backend('aws-ec2')
        self.client.enable_auth_backend('aws-ec2')

        # create a policy to associate with the role
        self.prep_policy('ec2rolepolicy')

        # attempt to get a list of roles before any exist
        no_roles = self.client.list_ec2_roles()
        # doing so should succeed and return None
        assert (no_roles is None)

        # test binding by AMI ID (the old way, to ensure backward compatibility)
        self.client.create_ec2_role('foo',
                                    'ami-notarealami',
                                    policies='ec2rolepolicy')

        # test binding by Account ID
        self.client.create_ec2_role('bar',
                                    bound_account_id='123456789012',
                                    policies='ec2rolepolicy')

        # test binding by IAM Role ARN
        self.client.create_ec2_role('baz',
                                    bound_iam_role_arn='arn:aws:iam::123456789012:role/mockec2role',
                                    policies='ec2rolepolicy')

        # test binding by instance profile ARN
        self.client.create_ec2_role('qux',
                                    bound_iam_instance_profile_arn='arn:aws:iam::123456789012:instance-profile/mockprofile',
                                    policies='ec2rolepolicy')

        roles = self.client.list_ec2_roles()

        assert('foo' in roles['data']['keys'])
        assert('bar' in roles['data']['keys'])
        assert('baz' in roles['data']['keys'])
        assert('qux' in roles['data']['keys'])

        foo_role = self.client.get_ec2_role('foo')
        assert(foo_role['data']['bound_ami_id'] == 'ami-notarealami')
        assert('ec2rolepolicy' in foo_role['data']['policies'])

        bar_role = self.client.get_ec2_role('bar')
        assert(bar_role['data']['bound_account_id'] == '123456789012')
        assert('ec2rolepolicy' in bar_role['data']['policies'])

        baz_role = self.client.get_ec2_role('baz')
        assert(baz_role['data']['bound_iam_role_arn'] == 'arn:aws:iam::123456789012:role/mockec2role')
        assert('ec2rolepolicy' in baz_role['data']['policies'])

        qux_role = self.client.get_ec2_role('qux')

        assert(qux_role['data']['bound_iam_instance_profile_arn'] == 'arn:aws:iam::123456789012:instance-profile/mockprofile')
        assert('ec2rolepolicy' in qux_role['data']['policies'])

        # teardown
        self.client.delete_ec2_role('foo')
        self.client.delete_ec2_role('bar')
        self.client.delete_ec2_role('baz')
        self.client.delete_ec2_role('qux')

        self.client.delete_policy('ec2rolepolicy')

        self.client.disable_auth_backend('aws-ec2')

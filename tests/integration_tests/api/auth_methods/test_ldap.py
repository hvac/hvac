import distutils.spawn
import logging
from unittest import TestCase, SkipTest

from parameterized import parameterized, param

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase
from tests.utils.mock_ldap_server import MockLdapServer


class TestLdap(HvacIntegrationTestCase, TestCase):
    TEST_LDAP_PATH = 'test-ldap'
    ldap_server = None

    @classmethod
    def setUpClass(cls):
        # The mock LDAP server requires Java runtime
        if not distutils.spawn.find_executable('java'):
            raise SkipTest('The mock LDAP server requires Java runtime')

        try:
            super(TestLdap, cls).setUpClass()
            logging.getLogger('ldap_test').setLevel(logging.ERROR)

            cls.mock_server_port = utils.get_free_port()
            cls.ldap_server = MockLdapServer()
            cls.ldap_server.start()
        except Exception:
            # Ensure that Vault server is taken down if setUpClass fails
            super(TestLdap, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestLdap, cls).tearDownClass()
        cls.ldap_server.stop()

    def setUp(self):
        super(TestLdap, self).setUp()
        if 'ldap/' not in self.client.list_auth_backends():
            self.client.sys.enable_auth_method(
                method_type='ldap',
                path=self.TEST_LDAP_PATH
            )

    def tearDown(self):
        super(TestLdap, self).tearDown()
        self.client.disable_auth_backend(
            mount_point=self.TEST_LDAP_PATH,
        )

    @parameterized.expand([
        ('update url', dict(url=MockLdapServer.ldap_url)),
        ('update binddn', dict(url=MockLdapServer.ldap_url, bind_dn='cn=vault,ou=Users,dc=hvac,dc=network')),
        ('update upn_domain', dict(url=MockLdapServer.ldap_url, upn_domain='python-hvac.org')),
        ('update certificate', dict(url=MockLdapServer.ldap_url, certificate=utils.load_config_file('server-cert.pem'))),
        ('update token_explicit_max_ttl', dict(url=MockLdapServer.ldap_url, token_explicit_max_ttl=28800)),
        ('token_bound_cidrs as list', dict(url=MockLdapServer.ldap_url, token_bound_cidrs=["192.168.26.30/16"])),
        ('incorrect tls version', dict(url=MockLdapServer.ldap_url, tls_min_version='cats'), exceptions.InvalidRequest,
         "invalid 'tls_min_version'"),
    ])
    def test_configure(self, test_label, parameters, raises=None, exception_message=''):
        parameters.update({
            'user_dn': MockLdapServer.ldap_users_dn,
            'group_dn': MockLdapServer.ldap_groups_dn,
            'mount_point': self.TEST_LDAP_PATH,
        })
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.ldap.configure(**parameters)
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            expected_status_code = 204
            configure_response = self.client.auth.ldap.configure(**parameters)
            self.assertEqual(
                first=expected_status_code,
                second=configure_response.status_code
            )

            read_config_response = self.client.auth.ldap.read_configuration(
                mount_point=self.TEST_LDAP_PATH,
            )
            for parameter, argument in parameters.items():
                if parameter == 'mount_point':
                    continue
                self.assertIn(
                    member=argument,
                    container=read_config_response['data'].values(),
                )

    def test_read_configuration(self):
        response = self.client.auth.ldap.read_configuration(
            mount_point=self.TEST_LDAP_PATH,
        )
        self.assertIn(
            member='data',
            container=response,
        )

    @parameterized.expand([
        ('no policies', 'cats'),
        ('policies as list', 'cats', ['purr-policy']),
        ('policies as invalid type', 'cats', 'purr-policy', exceptions.ParamValidationError, '"policies" argument must be an instance of list'),
    ])
    def test_create_or_update_group(self, test_label, name, policies=None, raises=None, exception_message=''):
        expected_status_code = 204
        if raises:
            with self.assertRaises(raises) as cm:
                create_response = self.client.auth.ldap.create_or_update_group(
                    name=name,
                    policies=policies,
                    mount_point=self.TEST_LDAP_PATH,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            create_response = self.client.auth.ldap.create_or_update_group(
                name=name,
                policies=policies,
                mount_point=self.TEST_LDAP_PATH,
            )
            self.assertEqual(
                first=expected_status_code,
                second=create_response.status_code
            )

    @parameterized.expand([
        ('read configured groups', 'cats'),
        ('non-existent groups', 'cats', False, exceptions.InvalidPath),
    ])
    def test_list_groups(self, test_label, name, configure_first=True, raises=None, exception_message=None):
        if configure_first:
            self.client.auth.ldap.create_or_update_group(
                name=name,
                mount_point=self.TEST_LDAP_PATH,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.ldap.list_groups(
                    mount_point=self.TEST_LDAP_PATH,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            list_groups_response = self.client.auth.ldap.list_groups(
                mount_point=self.TEST_LDAP_PATH,
            )
            # raise Exception(list_groups_response)
            self.assertDictEqual(
                d1=dict(keys=[name]),
                d2=list_groups_response['data'],
            )

    @parameterized.expand([
        ('read configured group', 'cats'),
        ('non-existent group', 'cats', False, exceptions.InvalidPath),
    ])
    def test_read_group(self, test_label, name, configure_first=True, raises=None, exception_message=None):
        if configure_first:
            self.client.auth.ldap.create_or_update_group(
                name=name,
                mount_point=self.TEST_LDAP_PATH,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.ldap.read_group(
                    name=name,
                    mount_point=self.TEST_LDAP_PATH,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            read_group_response = self.client.auth.ldap.read_group(
                name=name,
                mount_point=self.TEST_LDAP_PATH,
            )
            self.assertIn(
                member='policies',
                container=read_group_response['data'],
            )

    @parameterized.expand([
        ('no policies or groups', 'cats'),
        ('policies as list', 'cats', ['purr-policy']),
        ('policies as invalid type', 'cats', 'purr-policy', None, exceptions.ParamValidationError, '"policies" argument must be an instance of list'),
        ('no groups', 'cats', ['purr-policy']),
        ('groups as list', 'cats', None, ['meow-group']),
        ('groups as invalid type', 'cats', None, 'meow-group', exceptions.ParamValidationError, '"groups" argument must be an instance of list'),
    ])
    def test_create_or_update_user(self, test_label, username, policies=None, groups=None, raises=None, exception_message=''):
        expected_status_code = 204
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.ldap.create_or_update_user(
                    username=username,
                    policies=policies,
                    groups=groups,
                    mount_point=self.TEST_LDAP_PATH,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            create_response = self.client.auth.ldap.create_or_update_user(
                username=username,
                policies=policies,
                groups=groups,
                mount_point=self.TEST_LDAP_PATH,
            )
            self.assertEqual(
                first=expected_status_code,
                second=create_response.status_code
            )

    @parameterized.expand([
        ('read configured group', 'cats'),
        ('non-existent group', 'cats', False, exceptions.InvalidPath),
    ])
    def test_delete_group(self, test_label, name, configure_first=True, raises=None, exception_message=None):
        if configure_first:
            self.client.auth.ldap.create_or_update_group(
                name=name,
                mount_point=self.TEST_LDAP_PATH,
            )
        expected_status_code = 204
        delete_group_response = self.client.auth.ldap.delete_group(
            name=name,
            mount_point=self.TEST_LDAP_PATH,
        )
        self.assertEqual(
            first=expected_status_code,
            second=delete_group_response.status_code
        )

    @parameterized.expand([
        ('read configured user', 'cats'),
        ('non-existent user', 'cats', False, exceptions.InvalidPath),
    ])
    def test_list_users(self, test_label, username, configure_first=True, raises=None, exception_message=None):
        if configure_first:
            self.client.auth.ldap.create_or_update_user(
                username=username,
                mount_point=self.TEST_LDAP_PATH,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.ldap.list_users(
                    mount_point=self.TEST_LDAP_PATH,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            list_users_response = self.client.auth.ldap.list_users(
                mount_point=self.TEST_LDAP_PATH,
            )
            self.assertDictEqual(
                d1=dict(keys=[username]),
                d2=list_users_response['data'],
            )

    @parameterized.expand([
        ('read configured user', 'cats'),
        ('non-existent user', 'cats', False, exceptions.InvalidPath),
    ])
    def test_read_user(self, test_label, username, configure_first=True, raises=None, exception_message=None):
        if configure_first:
            self.client.auth.ldap.create_or_update_user(
                username=username,
                mount_point=self.TEST_LDAP_PATH,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.ldap.read_user(
                    username=username,
                    mount_point=self.TEST_LDAP_PATH,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            read_user_response = self.client.auth.ldap.read_user(
                username=username,
                mount_point=self.TEST_LDAP_PATH,
            )
            self.assertIn(
                member='policies',
                container=read_user_response['data'],
            )

    @parameterized.expand([
        ('read configured user', 'cats'),
        ('non-existent user', 'cats', False, exceptions.InvalidPath),
    ])
    def test_delete_user(self, test_label, username, configure_first=True, raises=None, exception_message=None):
        if configure_first:
            self.client.auth.ldap.create_or_update_user(
                username=username,
                mount_point=self.TEST_LDAP_PATH,
            )
        expected_status_code = 204
        delete_user_response = self.client.auth.ldap.delete_user(
            username=username,
            mount_point=self.TEST_LDAP_PATH,
        )
        self.assertEqual(
            first=expected_status_code,
            second=delete_user_response.status_code
        )

    @parameterized.expand([
        param(
            label='working creds with policy'
        ),
        param(
            label='invalid creds',
            username='not_your_dude_pal',
            password='some other dudes password',
            attach_policy=False,
            raises=exceptions.InvalidRequest,
        ),
        # The following two test cases cover either side of the associated changelog entry for LDAP auth here:
        # https://github.com/hashicorp/vault/blob/master/CHANGELOG.md#0103-june-20th-2018
        param(
            label='working creds no membership with Vault version >= 0.10.3',
            attach_policy=False,
            skip_due_to_vault_version=utils.vault_version_lt('0.10.3'),
        ),
        param(
            label='working creds no membership with Vault version < 0.10.3',
            attach_policy=False,
            raises=exceptions.InvalidRequest,
            exception_message='user is not a member of any authorized group',
            skip_due_to_vault_version=utils.vault_version_ge('0.10.3'),
        ),
    ])
    def test_login(self, label, username=None, password=None, attach_policy=True, raises=None,
                   exception_message='', skip_due_to_vault_version=False):
        if skip_due_to_vault_version:
            self.skipTest(reason='test case does not apply to Vault version under test')

        if username is None:
            username = self.ldap_server.ldap_user_name

        if password is None:
            password = self.ldap_server.ldap_user_password

        test_policy_name = 'test-ldap-policy'
        self.client.auth.ldap.configure(
            url=self.ldap_server.url,
            bind_dn=self.ldap_server.ldap_bind_dn,
            bind_pass=self.ldap_server.ldap_bind_password,
            user_dn=self.ldap_server.ldap_users_dn,
            user_attr='uid',
            group_dn=self.ldap_server.ldap_groups_dn,
            group_attr='cn',
            insecure_tls=True,
            mount_point=self.TEST_LDAP_PATH,
        )

        if attach_policy:
            self.prep_policy(test_policy_name)
            self.client.auth.ldap.create_or_update_group(
                name=self.ldap_server.ldap_group_name,
                policies=[test_policy_name],
                mount_point=self.TEST_LDAP_PATH,
            )

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.ldap.login(
                    username=username,
                    password=password,
                    mount_point=self.TEST_LDAP_PATH,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            login_response = self.client.auth.ldap.login(
                username=username,
                password=password,
                mount_point=self.TEST_LDAP_PATH,
            )
            self.assertDictEqual(
                d1=dict(username=username),
                d2=login_response['auth']['metadata'],
            )
            self.assertEqual(
                first=login_response['auth']['client_token'],
                second=self.client.token,
            )
            if attach_policy:
                expected_policies = ['default', test_policy_name]
            else:
                expected_policies = ['default']
            self.assertEqual(
                first=expected_policies,
                second=login_response['auth']['policies']
            )

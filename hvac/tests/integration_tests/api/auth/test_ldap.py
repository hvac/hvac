import logging
from unittest import TestCase

from ldap_test import LdapServer
from parameterized import parameterized

from hvac import exceptions
from hvac.tests import utils

LDAP_URL = 'ldap://ldap.hvac.network'
LDAP_GROUP_NAME = 'vault-users'
LDAP_USER_NAME = 'somedude'
LDAP_USER_PASSWORD = 'hvacrox'
LDAP_BASE_DC = 'hvac'
LDAP_BASE_DN = 'dc={dc},dc=network'.format(dc=LDAP_BASE_DC)
LDAP_BIND_DN = 'cn=admin,{base_dn}'.format(base_dn=LDAP_BASE_DN)
LDAP_BIND_PASSWORD = 'notaverygoodpassword'
LDAP_USERS_DN = 'dc=users,{base_dn}'.format(base_dn=LDAP_BASE_DN)
LDAP_GROUPS_OU = 'groups'
LDAP_GROUPS_DN = 'ou={ou},{base_dn}'.format(ou=LDAP_GROUPS_OU, base_dn=LDAP_BASE_DN)
LDAP_LOGIN_USER_DN = 'uid={username},{users_dn}'.format(username=LDAP_USER_NAME, users_dn=LDAP_USERS_DN)
LDAP_ENTRIES = [
    {
        'objectclass': 'domain',
        'dn': LDAP_USERS_DN,
        'attributes': {
            'dc': 'users'
        }
    },
    {
        'objectclass': ['inetOrgPerson', 'posixGroup', 'top'],
        'dn': LDAP_LOGIN_USER_DN,
        'attributes': {
            'uid': LDAP_USER_NAME,
            'userPassword': LDAP_USER_PASSWORD
        }
    },
    {
        'objectclass': 'organizationalUnit',
        'dn': LDAP_GROUPS_DN,
        'attributes': {
            'ou': 'groups',
        }
    },
    {
        'objectclass': 'groupOfNames',
        'dn': 'cn={cn},{groups_dn}'.format(cn=LDAP_GROUP_NAME, groups_dn=LDAP_GROUPS_DN),
        'attributes': {
            'cn': LDAP_GROUP_NAME,
            'member': LDAP_LOGIN_USER_DN,
        }
    },
]


class TestLdap(utils.HvacIntegrationTestCase, TestCase):
    ldap_server = None
    mock_server_port = None
    mock_ldap_url = None

    @classmethod
    def setUpClass(cls):
        super(TestLdap, cls).setUpClass()
        logging.getLogger('ldap_test').setLevel(logging.ERROR)

        cls.mock_server_port = utils.get_free_port()
        cls.mock_ldap_url = 'ldap://localhost:{port}'.format(port=cls.mock_server_port)
        cls.ldap_server = LdapServer({
            'port': cls.mock_server_port,
            'bind_dn': LDAP_BIND_DN,
            'password': LDAP_BIND_PASSWORD,
            'base': {
                'objectclass': ['domain'],
                'dn': LDAP_BASE_DN,
                'attributes': {'dc': LDAP_BASE_DC}
            },
            'entries': LDAP_ENTRIES,
        })
        cls.ldap_server.start()

    @classmethod
    def tearDownClass(cls):
        super(TestLdap, cls).tearDownClass()
        cls.ldap_server.stop()

    def setUp(self):
        super(TestLdap, self).setUp()
        if 'ldap/' not in self.client.list_auth_backends():
            self.client.enable_auth_backend(
                backend_type='ldap',
            )

    def tearDown(self):
        super(TestLdap, self).tearDown()
        for mount_point, configuration in self.client.list_auth_backends()['data'].items():
            if configuration.get('type') == 'ldap':
                self.client.disable_auth_backend(
                    mount_point=mount_point,
                )

    @parameterized.expand([
        ('update url', dict(url=LDAP_URL)),
        ('update binddn', dict(url=LDAP_URL, bind_dn='cn=vault,ou=Users,dc=hvac,dc=network')),
        ('update upn_domain', dict(url=LDAP_URL, upn_domain='hvac.network')),
        ('update certificate', dict(url=LDAP_URL, certificate=utils.load_test_data('server-cert.pem'))),
        ('incorrect tls version', dict(url=LDAP_URL, tls_min_version='cats'), exceptions.InvalidRequest,
         "invalid 'tls_min_version'"),
    ])
    def test_configure(self, test_label, parameters, raises=None, exception_message=''):
        parameters.update({
            'user_dn': LDAP_USERS_DN,
            'group_dn': LDAP_GROUPS_DN,
        })
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.ldap.configure(**parameters)
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            expected_status_code = 204
            configure_response = self.client.ldap.configure(**parameters)
            self.assertEqual(
                first=expected_status_code,
                second=configure_response.status_code
            )

            read_config_response = self.client.ldap.read_configuration()
            for parameter, argument in parameters.items():
                self.assertIn(
                    member=argument,
                    container=read_config_response['data'].values(),
                )

    def test_read_configuration(self):
        response = self.client.ldap.read_configuration()
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
                create_response = self.client.ldap.create_or_update_group(
                    name=name,
                    policies=policies,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            create_response = self.client.ldap.create_or_update_group(
                name=name,
                policies=policies,
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
            self.client.ldap.create_or_update_group(name=name)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.ldap.list_groups()
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            list_groups_response = self.client.ldap.list_groups()
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
            self.client.ldap.create_or_update_group(name=name)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.ldap.read_group(name=name)
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            read_group_response = self.client.ldap.read_group(name=name)
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
                self.client.ldap.create_or_update_user(
                    username=username,
                    policies=policies,
                    groups=groups,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            create_response = self.client.ldap.create_or_update_user(
                username=username,
                policies=policies,
                groups=groups,
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
            self.client.ldap.create_or_update_group(name=name)
        expected_status_code = 204
        delete_group_response = self.client.ldap.delete_group(name=name)
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
            self.client.ldap.create_or_update_user(username=username)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.ldap.list_users()
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            list_users_response = self.client.ldap.list_users()
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
            self.client.ldap.create_or_update_user(username=username)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.ldap.read_user(username=username)
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            read_user_response = self.client.ldap.read_user(username=username)
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
            self.client.ldap.create_or_update_user(username=username)
        expected_status_code = 204
        delete_user_response = self.client.ldap.delete_user(username=username)
        self.assertEqual(
            first=expected_status_code,
            second=delete_user_response.status_code
        )

    @parameterized.expand([
        ('working creds with policy', LDAP_USER_NAME, LDAP_USER_PASSWORD, True),
        ('working creds no membership', LDAP_USER_NAME, LDAP_USER_PASSWORD, False, exceptions.InvalidRequest,
         'user is not a member of any authorized group'),
        ('invalid creds', 'not_your_dude_pal', 'some other dudes password', False, exceptions.InvalidRequest,
         'ldap operation failed'),
    ])
    def test_login(self, test_label, username, password, attach_policy, raises=None, exception_message=''):
        test_policy_name = 'test-ldap-policy'
        self.client.ldap.configure(
            url=self.mock_ldap_url,
            bind_dn=self.ldap_server.config['bind_dn'],
            bind_pass=self.ldap_server.config['password'],
            user_dn=LDAP_USERS_DN,
            user_attr='uid',
            group_dn=LDAP_GROUPS_DN,
            group_attr='cn',
            insecure_tls=True,
        )

        if attach_policy:
            self.prep_policy(test_policy_name)
            self.client.ldap.create_or_update_group(
                name=LDAP_GROUP_NAME,
                policies=[test_policy_name],
            )

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.ldap.login(
                    username=username,
                    password=password,
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            login_response = self.client.ldap.login(
                username=username,
                password=password,
            )
            self.assertEqual(
                first=['default', test_policy_name],
                second=login_response['auth']['policies']
            )
            self.assertDictEqual(
                d1=dict(username=username),
                d2=login_response['auth']['metadata'],
            )
            self.assertEqual(
                first=login_response['auth']['client_token'],
                second=self.client.token,
            )

import logging
from unittest import TestCase
from unittest import skipIf

from parameterized import parameterized, param

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(utils.vault_version_lt('0.8.3'), "Kubernetes auth method not available before Vault version 0.8.3")
class TestKubernetes(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = 'kubernetes-test'

    def setUp(self):
        super(TestKubernetes, self).setUp()
        if '%s/' % self.TEST_MOUNT_POINT not in self.client.list_auth_backends():
            self.client.enable_auth_backend(
                backend_type='kubernetes',
                mount_point=self.TEST_MOUNT_POINT,
            )

    def tearDown(self):
        super(TestKubernetes, self).tearDown()
        self.client.disable_auth_backend(
            mount_point=self.TEST_MOUNT_POINT,
        )

    @parameterized.expand([
        param(
            'success',

        ),
        param(
            'set invalid kubernetes_ca_cert',
            kubernetes_ca_cert='ca_cert',
            raises=exceptions.ParamValidationError,
            exception_message='required type: PEM'
        ),
        param(
            'set invalid pem_key',
            kubernetes_ca_cert='-----BEGIN CERTIFICATE-----\\n.....\\n-----END CERTIFICATE-----',
            pem_keys=['pem_key'],
            raises=exceptions.ParamValidationError,
            exception_message='required type: PEM'
        ),
        param(
            'set invalid token_reviewer_jwt',
            kubernetes_ca_cert='-----BEGIN CERTIFICATE-----\\n.....\\n-----END CERTIFICATE-----',
            token_reviewer_jwt='reviewer_jwt',
            raises=exceptions.InternalServerError,
            exception_message='* not a compact JWS'
        )
    ])
    def test_configure(self, label, kubernetes_ca_cert=None, token_reviewer_jwt=None, pem_keys=None,
                       raises=None, exception_message=''):
        kubernetes_host = 'https://192.168.99.100:8443'
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.kubernetes.configure(
                    kubernetes_host=kubernetes_host,
                    kubernetes_ca_cert=kubernetes_ca_cert,
                    token_reviewer_jwt=token_reviewer_jwt,
                    pem_keys=pem_keys,
                    mount_point=self.TEST_MOUNT_POINT
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception)
            )
        else:
            configure_response = self.client.auth.kubernetes.configure(
                kubernetes_host=kubernetes_host,
                kubernetes_ca_cert='-----BEGIN CERTIFICATE-----\\n.....\\n-----END CERTIFICATE-----',
                mount_point=self.TEST_MOUNT_POINT
            )
            logging.debug('configure_response: %s' % configure_response)
            self.assertEqual(
                first=configure_response.status_code,
                second=204,
            )

    @parameterized.expand([
        param(
            'success',
        ),
        param(
            'no config written yet',
            write_config_first=False,
            raises=exceptions.InvalidPath
        )
    ])
    def test_read_config(self, label, write_config_first=True, raises=None):
        expected_config = {
            'kubernetes_host': 'https://192.168.99.100:8443',
            'kubernetes_ca_cert': '-----BEGIN CERTIFICATE-----\\n.....\\n-----END CERTIFICATE-----',
        }
        if write_config_first:
            self.client.auth.kubernetes.configure(
                mount_point=self.TEST_MOUNT_POINT,
                **expected_config
            )
        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.kubernetes.read_config(
                    mount_point=self.TEST_MOUNT_POINT,
                )
        else:
            read_config_response = self.client.auth.kubernetes.read_config(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('read_config_response: %s' % read_config_response)
            for k, v in expected_config.items():
                self.assertEqual(
                    first=v,
                    second=read_config_response[k],
                )

    @parameterized.expand([
        param(
            'success',
            bound_service_account_names=['vault-auth'],
            bound_service_account_namespaces=['default'],
        ),
        param(
            'both bounds wildcard',
            bound_service_account_names=['*'],
            bound_service_account_namespaces=['*'],
            raises=exceptions.ParamValidationError,
        ),
    ])
    def test_create_role(self, label, bound_service_account_names=None, bound_service_account_namespaces=None,
                         raises=None, exception_message=''):
        role_name = 'test-role'
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.kubernetes.create_role(
                    name=role_name,
                    bound_service_account_names=bound_service_account_names,
                    bound_service_account_namespaces=bound_service_account_namespaces,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            create_role_response = self.client.auth.kubernetes.create_role(
                name=role_name,
                bound_service_account_names=bound_service_account_names,
                bound_service_account_namespaces=bound_service_account_namespaces,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('create_role_response: %s' % create_role_response)
            self.assertEqual(
                first=create_role_response.status_code,
                second=204,
            )

    @parameterized.expand([
        param(
            'success',
        ),
        param(
            'nonexistent role name',
            create_role_first=False,
            raises=exceptions.InvalidPath,
        ),
    ])
    def test_read_role(self, label, create_role_first=True, raises=None, exception_message=''):
        role_name = 'test-role'
        expected_role_config = {
            'name': role_name,
            'bound_service_account_names': ['vault-auth'],
            'bound_service_account_namespaces': ['default'],
        }
        role_name = 'test-role'

        if create_role_first:
            self.client.auth.kubernetes.create_role(
                mount_point=self.TEST_MOUNT_POINT,
                **expected_role_config
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.kubernetes.read_role(
                    name=role_name,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_role_response = self.client.auth.kubernetes.read_role(
                name=role_name,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('read_role_response: %s' % read_role_response)
            self.assertEqual(
                first=read_role_response['bound_service_account_names'],
                second=expected_role_config['bound_service_account_names']
            )
            self.assertEqual(
                first=read_role_response['bound_service_account_namespaces'],
                second=expected_role_config['bound_service_account_namespaces']
            )

    @parameterized.expand([
        param(
            'success',
        ),
        param(
            'no roles',
            num_roles_to_create=0,
            raises=exceptions.InvalidPath,
        ),
        param(
            'no config',
            write_config_first=False,
        ),
    ])
    def test_list_roles(self, label, num_roles_to_create=1, write_config_first=True, raises=None):
        if write_config_first:
            self.client.auth.kubernetes.configure(
                kubernetes_host='https://192.168.99.100:8443',
                kubernetes_ca_cert='-----BEGIN CERTIFICATE-----\n.....\n-----END CERTIFICATE-----',
                mount_point=self.TEST_MOUNT_POINT,
            )
        roles_to_create = ['hvac{}'.format(str(n)) for n in range(0, num_roles_to_create)]
        bound_service_account_names = ['vault-auth']
        bound_service_account_namespaces = ['default']
        logging.debug('roles_to_create: %s' % roles_to_create)
        for role_to_create in roles_to_create:
            create_role_response = self.client.auth.kubernetes.create_role(
                name=role_to_create,
                bound_service_account_names=bound_service_account_names,
                bound_service_account_namespaces=bound_service_account_namespaces,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('create_role_response: %s' % create_role_response)

        if raises:
            with self.assertRaises(raises):
                self.client.auth.kubernetes.list_roles(
                    mount_point=self.TEST_MOUNT_POINT,
                )
        else:
            list_roles_response = self.client.auth.kubernetes.list_roles(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('list_roles_response: %s' % list_roles_response)
            self.assertEqual(
                first=list_roles_response['keys'],
                second=roles_to_create,
            )

    @parameterized.expand([
        param(
            'success',
        ),
        param(
            'nonexistent role name',
            configure_role_first=False,
        ),
    ])
    def test_delete_role(self, label, configure_role_first=True, raises=None):
        role_name = 'test-role'
        bound_service_account_names = ['vault-auth']
        bound_service_account_namespaces = ['default']
        if configure_role_first:
            create_role_response = self.client.auth.kubernetes.create_role(
                name=role_name,
                bound_service_account_names=bound_service_account_names,
                bound_service_account_namespaces=bound_service_account_namespaces,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('create_role_response: %s' % create_role_response)

        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.kubernetes.delete_role(
                    name=role_name,
                    mount_point=self.TEST_MOUNT_POINT,
                )
        else:
            delete_role_response = self.client.auth.kubernetes.delete_role(
                name=role_name,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('delete_role_response: %s' % delete_role_response)
            self.assertEqual(
                first=delete_role_response.status_code,
                second=204,
            )

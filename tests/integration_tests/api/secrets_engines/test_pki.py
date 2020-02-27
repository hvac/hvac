import logging
from unittest import TestCase

from parameterized import parameterized, param

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestPki(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = 'pki-integration-test'
    TEST_ROLE = 'role-test'

    def setUp(self):
        super(TestPki, self).setUp()
        self.client.enable_secret_backend(
            backend_type='pki',
            mount_point=self.TEST_MOUNT_POINT,
        )
        common_name = 'Vault integration tests'
        generate_type = 'exported'
        self.client.secrets.pki.generate_root(
            type=generate_type,
            common_name=common_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        name = self.TEST_ROLE
        self.client.secrets.pki.create_or_update_role(
            name=name,
            extra_params={
                'allow_any_name': True,
                'ttl': '6h',
                'max_ttl': '12h',
                },
            mount_point=self.TEST_MOUNT_POINT,
        )

    def tearDown(self):
        self.client.disable_secret_backend(mount_point=self.TEST_MOUNT_POINT)
        super(TestPki, self).tearDown()

    # Read CA Certificate
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_read_ca_certificate(self, label, raises=False, exception_message=''):
        read_ca_certificate_response = self.client.secrets.pki.read_ca_certificate(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('read_ca_certificate_response: %s' % read_ca_certificate_response)
        self.assertIsInstance(
            obj=read_ca_certificate_response,
            cls=str,
        )

    # Read CA Certificate Chain
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_read_ca_certificate_chain(self, label, raises=False, exception_message=''):
        read_ca_certificate_chain_response = self.client.secrets.pki.read_ca_certificate_chain(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('read_ca_certificate_chain_response: %s' % read_ca_certificate_chain_response)
        self.assertIsInstance(
            obj=read_ca_certificate_chain_response,
            cls=str,
        )

    # Read Certificate
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_read_certificate(self, label, raises=False, exception_message=''):
        list_certificates_response = self.client.secrets.pki.list_certificates(
            mount_point=self.TEST_MOUNT_POINT,
        )

        serial = list_certificates_response['data']['keys'][0]
        read_certificate_response = self.client.secrets.pki.read_certificate(
            serial=serial,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('read_certificate_response: %s' % read_certificate_response)
        self.assertIsInstance(
            obj=read_certificate_response,
            cls=dict,
        )

    # List Certificates
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_list_certificates(self, label, raises=False, exception_message=''):
        list_certificates_response = self.client.secrets.pki.list_certificates(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('list_certificates_response: %s' % list_certificates_response)
        self.assertIsInstance(
            obj=list_certificates_response,
            cls=dict,
        )

    # Submit CA Information
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_submit_ca_information(self, label, raises=False, exception_message=''):
        pem_bundle = '{ca_key}{ca_crt}'.format(
            ca_key=''.join(open(utils.get_config_file_path('ca-key.pem')).readlines()),
            ca_crt=''.join(open(utils.get_config_file_path('ca-cert.pem')).readlines()),
        )
        submit_ca_information_response = self.client.secrets.pki.submit_ca_information(
            pem_bundle=pem_bundle,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('submit_ca_information_response: %s' % submit_ca_information_response)
        self.assertEqual(
            first=submit_ca_information_response.status_code,
            second=204,
        )

    # Read CRL Configuration
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_read_crl_configuration(self, label, raises=False, exception_message=''):
        expiry = '72h'
        self.client.secrets.pki.set_crl_configuration(
            expiry=expiry,
            mount_point=self.TEST_MOUNT_POINT,
        )

        read_crl_configuration_response = self.client.secrets.pki.read_crl_configuration(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('read_crl_configuration_response: %s' % read_crl_configuration_response)
        self.assertIsInstance(
            obj=read_crl_configuration_response,
            cls=dict,
        )

    # Set CRL Configuration
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_set_crl_configuration(self, label, raises=False, exception_message=''):
        expiry = '72h'
        disable = False
        set_crl_configuration_response = self.client.secrets.pki.set_crl_configuration(
            expiry=expiry,
            disable=disable,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('set_crl_configuration_response: %s' % set_crl_configuration_response)
        self.assertEqual(
            first=set_crl_configuration_response.status_code,
            second=204,
        )

    # Read URLs
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_read_urls(self, label, raises=False, exception_message=''):
        params = {
                'issuing_certificates': ['http://127.0.0.1:8200/v1/pki/ca'],
                'crl_distribution_points': ['http://127.0.0.1:8200/v1/pki/crl']
                }
        self.client.secrets.pki.set_urls(
            params=params,
            mount_point=self.TEST_MOUNT_POINT,
        )
        read_urls_response = self.client.secrets.pki.read_urls(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('read_urls_response: %s' % read_urls_response)
        self.assertIsInstance(
            obj=read_urls_response,
            cls=dict,
        )

    # Set URLs
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_set_urls(self, label, raises=False, exception_message=''):
        params = {
                'issuing_certificates': ['http://127.0.0.1:8200/v1/pki/ca'],
                'crl_distribution_points': ['http://127.0.0.1:8200/v1/pki/crl']
                }
        set_urls_response = self.client.secrets.pki.set_urls(
            params=params,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('set_urls_response: %s' % set_urls_response)
        self.assertEqual(
            first=set_urls_response.status_code,
            second=204,
        )

    # Read CRL
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_read_crl(self, label, raises=False, exception_message=''):
        expiry = '72h'
        self.client.secrets.pki.set_crl_configuration(
            expiry=expiry,
            mount_point=self.TEST_MOUNT_POINT,
        )

        read_crl_response = self.client.secrets.pki.read_crl(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('read_crl_response: %s' % read_crl_response)
        self.assertIsInstance(
            obj=read_crl_response,
            cls=str,
        )

    # Rotate CRLs
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_rotate_crl(self, label, raises=False, exception_message=''):
        rotate_crl_response = self.client.secrets.pki.rotate_crl(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('rotate_crl_response: %s' % rotate_crl_response)
        self.assertIsInstance(
            obj=rotate_crl_response,
            cls=dict,
        )

    # Generate Intermediate
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_generate_intermediate(self, label, raises=False, exception_message=''):
        common_name = 'Vault integration tests'
        generate_type = 'exported'
        generate_intermediate_response = self.client.secrets.pki.generate_intermediate(
            type=generate_type,
            common_name=common_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('generate_intermediate_response: %s' % generate_intermediate_response)
        self.assertEqual(
            first=generate_intermediate_response.status_code,
            second=200,
        )

    # Set Signed Intermediate
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_set_signed_intermediate(self, label, raises=False, exception_message=''):
        # Generate intermediate CA mount point
        ca_intermediate_pki_mount_point = '{}-signed-intermediate-ca'.format(self.TEST_MOUNT_POINT)
        self.client.enable_secret_backend(
            backend_type='pki',
            mount_point=ca_intermediate_pki_mount_point,
        )
        # Generate intermediate CA
        common_name = 'Vault integration tests intermediate CA'
        generate_type = 'exported'
        generate_intermediate_response = self.client.secrets.pki.generate_intermediate(
            type=generate_type,
            common_name=common_name,
            mount_point=ca_intermediate_pki_mount_point,
        )
        logging.debug('generate_intermediate_response: %s' % generate_intermediate_response.json())
        csr = generate_intermediate_response.json()['data']['csr']

        # Sign intermediate CA
        sign_intermediate_response = self.client.secrets.pki.sign_intermediate(
            csr=csr,
            common_name=common_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('sign_intermediate_response: %s' % sign_intermediate_response)
        certificate = sign_intermediate_response.json()['data']['certificate']

        # Finally test Set Signed Intermediate
        set_signed_intermediate_response = self.client.secrets.pki.set_signed_intermediate(
            certificate=certificate,
            mount_point=ca_intermediate_pki_mount_point,
        )
        logging.debug('set_signed_intermediate_response: %s' % set_signed_intermediate_response)
        self.assertEqual(
            first=set_signed_intermediate_response.status_code,
            second=204,
        )

        # Now clean intermediate CA
        self.client.disable_secret_backend(mount_point=ca_intermediate_pki_mount_point)

    # Generate Certificate
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_generate_certificate(self, label, raises=False, exception_message=''):
        name = self.TEST_ROLE
        common_name = 'test.example.com'
        generate_certificate_response = self.client.secrets.pki.generate_certificate(
            name=name,
            common_name=common_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('generate_certificate_response: %s' % generate_certificate_response)
        self.assertEqual(
            first=generate_certificate_response.status_code,
            second=200,
        )

    # Revoke Certificate
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_revoke_certificate(self, label, raises=False, exception_message=''):
        name = self.TEST_ROLE
        common_name = 'test.example.com'
        generate_certificate_response = self.client.secrets.pki.generate_certificate(
            name=name,
            common_name=common_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('generate_certificate_response: %s' % generate_certificate_response)
        serial_number = generate_certificate_response.json()['data']['serial_number']
        logging.debug('serial_number: %s' % serial_number)
        revoke_certificate_response = self.client.secrets.pki.revoke_certificate(
            serial_number=serial_number,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('revoke_certificate_response: %s' % revoke_certificate_response)
        self.assertEqual(
            first=revoke_certificate_response.status_code,
            second=200,
        )

    # Create/Update Role
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_create_or_update_role(self, label, raises=False, exception_message=''):
        name = '{}-2'.format(self.TEST_ROLE)
        create_or_update_role_response = self.client.secrets.pki.create_or_update_role(
            name=name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('create_or_update_role_response: %s' % create_or_update_role_response)
        self.assertEqual(
            first=create_or_update_role_response.status_code,
            second=204,
        )

    # Read Role
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_read_role(self, label, raises=False, exception_message=''):
        read_role_response = self.client.secrets.pki.read_role(
            name=self.TEST_ROLE,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('read_role_response: %s' % read_role_response)
        self.assertIsInstance(
            obj=read_role_response,
            cls=dict,
        )

    # List Roles
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_list_roles(self, label, raises=False, exception_message=''):
        list_roles_response = self.client.secrets.pki.list_roles(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('list_roles_response: %s' % list_roles_response)
        self.assertIsInstance(
            obj=list_roles_response,
            cls=dict,
        )

    # Delete Role
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_delete_role(self, label, raises=False, exception_message=''):
        name = '{}-2'.format(self.TEST_ROLE)
        self.client.secrets.pki.create_or_update_role(
            name=name,
            mount_point=self.TEST_MOUNT_POINT,
        )

        delete_role_response = self.client.secrets.pki.delete_role(
            name=name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('delete_role_response: %s' % delete_role_response)
        self.assertEqual(
            first=delete_role_response.status_code,
            second=204,
        )

    # Generate Root
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_generate_root(self, label, raises=False, exception_message=''):
        ca_pki_mount_point = '{}-test-ca'.format(self.TEST_MOUNT_POINT)
        self.client.enable_secret_backend(
            backend_type='pki',
            mount_point=ca_pki_mount_point,
        )
        common_name = 'Vault integration tests'
        generate_type = 'exported'
        generate_root_response = self.client.secrets.pki.generate_root(
            type=generate_type,
            common_name=common_name,
            mount_point=ca_pki_mount_point,
        )
        logging.debug('generate_root_response: %s' % generate_root_response)
        self.assertEqual(
            first=generate_root_response.status_code,
            second=200,
        )
        self.client.disable_secret_backend(mount_point=ca_pki_mount_point)

    # Delete Root
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_delete_root(self, label, raises=False, exception_message=''):
        ca_pki_mount_point = '{}-test-ca'.format(self.TEST_MOUNT_POINT)
        self.client.enable_secret_backend(
            backend_type='pki',
            mount_point=ca_pki_mount_point,
        )
        common_name = 'Vault integration tests'
        generate_type = 'exported'
        self.client.secrets.pki.generate_root(
            type=generate_type,
            common_name=common_name,
            mount_point=ca_pki_mount_point,
        )

        delete_root_response = self.client.secrets.pki.delete_root(
            mount_point=ca_pki_mount_point,
        )
        logging.debug('delete_root_response: %s' % delete_root_response)
        self.assertEqual(
            first=delete_root_response.status_code,
            second=204,
        )
        self.client.disable_secret_backend(mount_point=ca_pki_mount_point)

    # Sign Intermediate
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_sign_intermediate(self, label, raises=False, exception_message=''):
        # Generate intermediate CA
        ca_intermediate_pki_mount_point = '{}-intermediate-ca'.format(self.TEST_MOUNT_POINT)
        self.client.enable_secret_backend(
            backend_type='pki',
            mount_point=ca_intermediate_pki_mount_point,
        )
        common_name = 'Vault integration tests intermediate CA'
        generate_type = 'exported'
        generate_intermediate_response = self.client.secrets.pki.generate_intermediate(
            type=generate_type,
            common_name=common_name,
            mount_point=ca_intermediate_pki_mount_point,
        )
        logging.debug('generate_intermediate_response: %s' % generate_intermediate_response.json())
        csr = generate_intermediate_response.json()['data']['csr']

        sign_intermediate_response = self.client.secrets.pki.sign_intermediate(
            csr=csr,
            common_name=common_name,
            extra_params={'use_csr_values': True},
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('sign_intermediate_response: %s' % sign_intermediate_response)
        self.assertEqual(
            first=sign_intermediate_response.status_code,
            second=200,
        )
        # Now clean intermediate CA
        self.client.disable_secret_backend(mount_point=ca_intermediate_pki_mount_point)

    # Sign Self-Issued
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_sign_self_issued(self, label, raises=False, exception_message=''):
        sign_self_issued_response = self.client.secrets.pki.sign_self_issued(
            certificate=''.join(open(utils.get_config_file_path('ca-cert.pem')).readlines()),
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('sign_self_issued_response: %s' % sign_self_issued_response)
        self.assertEqual(
            first=sign_self_issued_response.status_code,
            second=200,
        )

    # Sign Certificate
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_sign_certificate(self, label, raises=False, exception_message=''):
        name = self.TEST_ROLE
        common_name = 'another.example.com'
        sign_certificate_response = self.client.secrets.pki.sign_certificate(
            name=name,
            csr=''.join(open(utils.get_config_file_path('server-cert.csr')).readlines()),
            common_name=common_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('sign_certificate_response: %s' % sign_certificate_response)
        self.assertEqual(
            first=sign_certificate_response.status_code,
            second=200,
        )

    # Sign Verbatim
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_sign_verbatim(self, label, raises=False, exception_message=''):
        name = self.TEST_ROLE
        sign_verbatim_response = self.client.secrets.pki.sign_verbatim(
            csr=''.join(open(utils.get_config_file_path('server-cert.csr')).readlines()),
            name=name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('sign_verbatim_response: %s' % sign_verbatim_response)
        self.assertEqual(
            first=sign_verbatim_response.status_code,
            second=200,
        )

    # Tidy
    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_tidy(self, label, raises=False, exception_message=''):
        tidy_response = self.client.secrets.pki.tidy(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug('tidy_response: %s' % tidy_response)
        self.assertEqual(
            first=tidy_response.status_code,
            second=202,
        )

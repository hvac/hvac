#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
from threading import Thread
from unittest import TestCase

from parameterized import parameterized, param

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase
from tests.utils.mock_aws_request_handler import MockAWSRequestHandler

try:
    # Python 2.7
    from http.server import HTTPServer
except ImportError:
    # Python 3.x
    from BaseHTTPServer import HTTPServer


class TestAws(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = 'aws-test'
    TEST_ROLE_NAME = 'hvac-test-role'

    @classmethod
    def setUpClass(cls):
        super(TestAws, cls).setUpClass()
        # Configure mock server.
        cls.mock_server_port = utils.get_free_port()
        cls.mock_server = HTTPServer(('localhost', cls.mock_server_port), MockAWSRequestHandler)

        # Start running mock server in a separate thread.
        # Daemon threads automatically shut down when the main process exits.
        cls.mock_server_thread = Thread(target=cls.mock_server.serve_forever)
        cls.mock_server_thread.setDaemon(True)
        cls.mock_server_thread.start()

    def setUp(self):
        super(TestAws, self).setUp()
        if '%s/' % self.TEST_MOUNT_POINT not in self.client.list_auth_backends():
            self.client.sys.enable_secrets_engine(
                backend_type='aws',
                path=self.TEST_MOUNT_POINT,
            )

    def tearDown(self):
        self.client.sys.disable_secrets_engine(
            path=self.TEST_MOUNT_POINT,
        )
        super(TestAws, self).tearDown()

    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_configure_root_iam_credentials(self, label, credentials='', raises=None, exception_message=''):
        access_key = 'butts'
        secret_key = 'secret-butts'
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.configure_root_iam_credentials(
                    access_key=access_key,
                    secret_key=secret_key,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            configure_response = self.client.secrets.aws.configure_root_iam_credentials(
                access_key=access_key,
                secret_key=secret_key,
                iam_endpoint='localhost',
                sts_endpoint='localhost',
                mount_point=self.TEST_MOUNT_POINT,
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
    ])
    def test_configure_lease(self, label, lease='60s', lease_max='120s', raises=None, exception_message=''):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.configure_lease(
                    lease=lease,
                    lease_max=lease_max,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            configure_response = self.client.secrets.aws.configure_lease(
                lease=lease,
                lease_max=lease_max,
                mount_point=self.TEST_MOUNT_POINT,
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
    ])
    def test_read_lease(self, label, lease='60s', lease_max='120s', configure_first=True, raises=None, exception_message=''):
        if configure_first:
            configure_response = self.client.secrets.aws.configure_lease(
                lease=lease,
                lease_max=lease_max,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('configure_response: %s' % configure_response)

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.read_lease_config(
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_response = self.client.secrets.aws.read_lease_config(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('read_response: %s' % read_response)
            self.assertEqual(
                first=int(lease_max.replace('s', '')),
                second=self.convert_python_ttl_value_to_expected_vault_response(
                    ttl_value=read_response['data']['lease_max'],
                ),
            )

    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_create_or_update_role(self, label, credential_type='iam_user', policy_document=None, default_sts_ttl=None,
                                   max_sts_ttl=None, role_arns=None, policy_arns=None, raises=None,
                                   exception_message=''):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.create_or_update_role(
                    name=self.TEST_ROLE_NAME,
                    credential_type=credential_type,
                    policy_document=policy_document,
                    default_sts_ttl=default_sts_ttl,
                    max_sts_ttl=max_sts_ttl,
                    role_arns=role_arns,
                    policy_arns=policy_arns,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            role_response = self.client.secrets.aws.create_or_update_role(
                name=self.TEST_ROLE_NAME,
                credential_type=credential_type,
                policy_document=policy_document,
                default_sts_ttl=default_sts_ttl,
                max_sts_ttl=max_sts_ttl,
                role_arns=role_arns,
                policy_arns=policy_arns,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('role_response: %s' % role_response)
            self.assertEqual(
                first=role_response.status_code,
                second=204,
            )

    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_read_role(self, label, configure_first=True, raises=None, exception_message=''):
        if configure_first:
            self.client.secrets.aws.create_or_update_role(
                name=self.TEST_ROLE_NAME,
                credential_type='iam_user',
                mount_point=self.TEST_MOUNT_POINT,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.read_role(
                    name=self.TEST_ROLE_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_role_response = self.client.secrets.aws.read_role(
                name=self.TEST_ROLE_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('read_role_response: %s' % read_role_response)
            self.assertEqual(
                first=read_role_response['data']['credential_types'],
                second=['iam_user'],
            )

    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_list_roles(self, label, configure_first=True, raises=None, exception_message=''):
        if configure_first:
            self.client.secrets.aws.create_or_update_role(
                name=self.TEST_ROLE_NAME,
                credential_type='iam_user',
                mount_point=self.TEST_MOUNT_POINT,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.list_roles(
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            list_roles_response = self.client.secrets.aws.list_roles(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('list_roles_response: %s' % list_roles_response)
            self.assertEqual(
                first=list_roles_response['data']['keys'],
                second=[self.TEST_ROLE_NAME],
            )

    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_delete_role(self, label, configure_first=True, raises=None, exception_message=''):
        if configure_first:
            self.client.secrets.aws.create_or_update_role(
                name=self.TEST_ROLE_NAME,
                credential_type='iam_user',
                mount_point=self.TEST_MOUNT_POINT,
            )
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.aws.delete_role(
                    name=self.TEST_ROLE_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            delete_role_response = self.client.secrets.aws.delete_role(
                name=self.TEST_ROLE_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('delete_role_response: %s' % delete_role_response)
            self.assertEqual(
                first=delete_role_response.status_code,
                second=204,
            )

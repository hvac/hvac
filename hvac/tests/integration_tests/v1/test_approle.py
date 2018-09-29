import logging
from unittest import TestCase

from parameterized import parameterized, param

from hvac import exceptions
from hvac.tests import utils


class TestApprole(utils.HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = 'test-approle'

    def setUp(self):
        super(TestApprole, self).setUp()
        self.client.enable_auth_backend(
            backend_type='approle',
            mount_point=self.TEST_MOUNT_POINT,
        )

    def tearDown(self):
        self.client.disable_auth_backend(mount_point=self.TEST_MOUNT_POINT)
        super(TestApprole, self).tearDown()

    @parameterized.expand([
        param(
            'no secret ids',
            num_secrets_to_create=0,
            raises=exceptions.InvalidPath,
        ),
        param(
            'one secret id',
            num_secrets_to_create=1,
        ),
        param(
            'two secret ids',
            num_secrets_to_create=2,
        ),
    ])
    def test_list_role_secrets(self, label, num_secrets_to_create=0, raises=None):
        test_role_name = 'testrole'
        self.client.create_role(
            role_name=test_role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        for _ in range(0, num_secrets_to_create):
            self.client.create_role_secret_id(
                role_name=test_role_name,
                mount_point=self.TEST_MOUNT_POINT,
            )

        if raises:
            with self.assertRaises(raises):
                self.client.list_role_secrets(
                    role_name=test_role_name,
                    mount_point=self.TEST_MOUNT_POINT,
                )
        else:
            list_role_secrets_response = self.client.list_role_secrets(
                role_name=test_role_name,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('list_role_secrets_response: %s' % list_role_secrets_response)
            self.assertEqual(
                first=num_secrets_to_create,
                second=len(list_role_secrets_response['data']['keys'])
            )

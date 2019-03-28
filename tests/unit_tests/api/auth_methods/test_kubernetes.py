import logging
from unittest import TestCase
from unittest import skipIf

import requests_mock
from parameterized import parameterized

from hvac.adapters import Request
from hvac.api.auth_methods import Kubernetes
from tests import utils


@skipIf(utils.vault_version_lt('0.8.3'), "Kubernetes auth method not available before Vault version 0.8.3")
class TestKubernetes(TestCase):
    TEST_MOUNT_POINT = 'kubernetes-test'

    @parameterized.expand([
        ('success', dict(), None,),
    ])
    @requests_mock.Mocker()
    def test_login(self, label, test_params, raises, requests_mocker):
        role_name = 'hvac'
        test_policies = [
            "default",
            "dev",
            "prod",
        ]
        expected_status_code = 200
        mock_url = 'http://localhost:8200/v1/auth/{mount_point}/login'.format(
            mount_point=self.TEST_MOUNT_POINT,
        )
        mock_response = {
            "auth": {
                "client_token": "38fe9691-e623-7238-f618-c94d4e7bc674",
                "accessor": "78e87a38-84ed-2692-538f-ca8b9f400ab3",
                "policies": test_policies,
                "metadata": {
                    "role": role_name,
                    "service_account_name": "vault-auth",
                    "service_account_namespace": "default",
                    "service_account_secret_name": "vault-auth-token-pd21c",
                    "service_account_uid": "aa9aa8ff-98d0-11e7-9bb7-0800276d99bf"
                },
                "lease_duration": 2764800,
                "renewable": True,
            },
        }
        requests_mocker.register_uri(
            method='POST',
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        kubernetes = Kubernetes(adapter=Request())
        if raises is not None:
            with self.assertRaises(raises):
                kubernetes.login(
                    role=role_name,
                    jwt='my-jwt',
                    mount_point=self.TEST_MOUNT_POINT,
                    **test_params
                )
        else:
            login_response = kubernetes.login(
                role=role_name,
                jwt='my-jwt',
                mount_point=self.TEST_MOUNT_POINT,
                **test_params
            )
            logging.debug('login_response: %s' % login_response)
            self.assertEqual(
                first=login_response['auth']['policies'],
                second=test_policies,
            )

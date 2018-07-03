from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac import Client


class TestKubernetesMethods(TestCase):
    """Unit tests providing coverage for Kubernetes auth backend-related methods/routes."""

    @parameterized.expand([
        ("default mount point", "custom_role", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", None),
        ("custom mount point", "custom_role", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "kube-not-default")
    ])
    @requests_mock.Mocker()
    def test_auth_kubernetes(self, test_label, test_role, test_jwt, mount_point, requests_mocker):
        mock_response = {
            'auth': {
                'accessor': 'accessor-1234-5678-9012-345678901234',
                'client_token': 'cltoken-1234-5678-9012-345678901234',
                'lease_duration': 10000,
                'metadata': {
                    'role': 'custom_role',
                    'service_account_name': 'vault-auth',
                    'service_account_namespace': 'default',
                    'service_account_secret_name': 'vault-auth-token-pd21c',
                    'service_account_uid': 'aa9aa8ff-98d0-11e7-9bb7-0800276d99bf'
                },
                'policies': [
                    'default',
                    'custom_role'
                ],
                'renewable': True
            },
            'data': None,
            'lease_duration': 0,
            'lease_id': '',
            'renewable': False,
            'request_id': 'requesti-1234-5678-9012-345678901234',
            'warnings': [],
            'wrap_info': None
        }
        mock_url = 'http://localhost:8200/v1/auth/{0}/login'.format(
                'kubernetes' if mount_point is None else mount_point)
        requests_mocker.register_uri(
            method='POST',
            url=mock_url,
            json=mock_response
        )
        client = Client()

        if mount_point is None:
            actual_response = client.auth_kubernetes(
                role=test_role,
                jwt=test_jwt
            )
        else:
            actual_response = client.auth_kubernetes(
                role=test_role,
                jwt=test_jwt,
                mount_point=mount_point
            )

        # ensure we received our mock response data back successfully
        self.assertEqual(mock_response, actual_response)

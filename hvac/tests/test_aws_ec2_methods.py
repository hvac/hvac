from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac import Client


class TestAwsEc2Methods(TestCase):
    """Unit tests providing coverage for AWS (EC2) auth backend-related methods/routes."""

    @parameterized.expand([
        ("default mount point", None),
        ("custom mount point", 'aws-ec2'),
    ])
    @requests_mock.Mocker()
    def test_auth_ec2(self, test_label, mount_point, requests_mocker):
        mock_response = {
            'auth': {
                'accessor': 'accessor-1234-5678-9012-345678901234',
                'client_token': 'cltoken-1234-5678-9012-345678901234',
                'lease_duration': 10000,
                'metadata': {
                    'account_id': '12345678912',
                    'ami_id': 'ami-someami',
                    'instance_id': 'i-instanceid',
                    'nonce': 'thenonce-1234-5678-9012-345678901234',
                    'region': 'us-east-1',
                    'role': 'custom_role',
                    'role_tag_max_ttl': '0s'
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
            'aws-ec2' if mount_point is None else mount_point
        )
        requests_mocker.register_uri(
            method='POST',
            url=mock_url,
            json=mock_response
        )
        client = Client()

        if mount_point is None:
            actual_response = client.auth_ec2(
                pkcs7='mock_pcks7'
            )
        else:
            actual_response = client.auth_ec2(
                pkcs7='mock_pcks7',
                mount_point=mount_point
            )

        # ensure we received our mock response data back successfully
        self.assertEqual(mock_response, actual_response)

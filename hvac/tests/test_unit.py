from unittest import TestCase

import requests_mock

from hvac import Client


class UnitTest(TestCase):

    @requests_mock.Mocker()
    def test_auth_ec2(self, requests_mocker):
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
        test_mount_point = 'aws-ec2'
        requests_mocker.register_uri('POST', 'http://localhost:8200/v1/auth/{0}/login'.format(test_mount_point), json=mock_response)
        client = Client()
        actual_response = client.auth_ec2('mock_pcks7')

        # ensure we received our mock response data back successfully
        self.assertEqual(mock_response, actual_response)

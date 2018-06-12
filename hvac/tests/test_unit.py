import json
from base64 import b64decode
from datetime import datetime
from unittest import TestCase

import mock
import requests_mock

from hvac import Client


class UnitTest(TestCase):

    @mock.patch('hvac.aws_utils.datetime')
    @mock.patch('hvac.v1.Client.auth')
    def test_auth_aws_iam(self, auth_mock, datetime_mock):
        datetime_mock.utcnow.return_value = datetime(2015, 8, 30, 12, 36, 0)

        client = Client()
        client.auth_aws_iam('AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY')

        auth_mock.assert_called()
        args, kwargs = auth_mock.call_args
        actual_params = kwargs['json']

        actual_iam_http_request_method = actual_params['iam_http_request_method']
        self.assertEqual('POST', actual_iam_http_request_method)

        actual_iam_request_url = b64decode(actual_params['iam_request_url']).decode('utf-8')
        self.assertEqual('https://sts.amazonaws.com/', actual_iam_request_url)

        expected_iam_request_headers = {
            'Authorization': ['AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date, Signature=0268ea4a725deae1116f5228d6b177fb047f9f3a9e1c5fd4baa0dc1fbb0d1a99'],
            'Content-Length': ['43'],
            'Content-Type': ['application/x-www-form-urlencoded; charset=utf-8'],
            'Host': ['sts.amazonaws.com'],
            'X-Amz-Date': ['20150830T123600Z'],
        }
        actual_iam_request_headers = json.loads(b64decode(actual_params['iam_request_headers']))
        self.assertEqual(expected_iam_request_headers, actual_iam_request_headers)

        actual_iam_request_body = b64decode(actual_params['iam_request_body']).decode('utf-8')
        self.assertEqual('Action=GetCallerIdentity&Version=2011-06-15', actual_iam_request_body)

        actual_role = actual_params['role']
        self.assertEqual('', actual_role)

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

from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac.adapters import Request
from hvac.api.secrets_engines import Gcp
from hvac.api.secrets_engines.gcp import DEFAULT_MOUNT_POINT


class TestGcp(TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestGcp, cls).setUpClass()

    def setUp(self):
        super(TestGcp, self).setUp()

    def tearDown(self):
        super(TestGcp, self).tearDown()

    
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_write_config(self, test_label, requests_mocker):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_read_config(self, test_label, requests_mocker):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_create_or_update_roleset(self, test_label, requests_mocker):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_rotate_roleset_account(self, test_label, requests_mocker):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_rotate_roleset_account_key_access_token_roleset_only(self, test_label, requests_mocker):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_read_roleset(self, test_label, requests_mocker):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_list_rolesets(self, test_label, requests_mocker):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_generate_secret_iam_service_account_creds_oauth2_access_token(self, test_label, requests_mocker):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_generate_secret_iam_service_account_creds_service_account_key(self, test_label, requests_mocker):
        raise NotImplementedError
    
from unittest import TestCase

from parameterized import parameterized

from hvac.api.secrets_engines.gcp import DEFAULT_MOUNT_POINT
from hvac.tests import utils


class TestGcp(utils.HvacIntegrationTestCase, TestCase):

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
    def test_write_config(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_read_config(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_create_or_update_roleset(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_rotate_roleset_account(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_rotate_roleset_account_key_access_token_roleset_only(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_read_roleset(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_list_rolesets(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_generate_secret_iam_service_account_creds_oauth2_access_token(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_generate_secret_iam_service_account_creds_service_account_key(self, test_label):
        raise NotImplementedError
    
from unittest import TestCase

from parameterized import parameterized

from hvac.api.secrets_engines.aws import DEFAULT_MOUNT_POINT
from hvac.tests import utils


class TestAws(utils.HvacIntegrationTestCase, TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestAws, cls).setUpClass()

    def setUp(self):
        super(TestAws, self).setUp()

    def tearDown(self):
        super(TestAws, self).tearDown()

    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_configure_root_iam_credentials(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_rotate_root_iam_credentials(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_configure_lease(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_read_lease(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_create_or_update_role(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_read_role(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_list_roles(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_delete_role(self, test_label):
        raise NotImplementedError
    
    @parameterized.expand([
        ('some_test',),
    ])
    def test_generate_credentials(self, test_label):
        raise NotImplementedError
    
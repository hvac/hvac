from unittest import TestCase

from parameterized import parameterized

from hvac.api.auth.gcp import DEFAULT_MOUNT_POINT
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
    def test_configure(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_read_config(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_delete_config(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_create_role(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_edit_service_accounts_on_iam_role(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_edit_labels_on_gce_role(self, test_label):
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
    def test_login(self, test_label):
        raise NotImplementedError

from unittest import TestCase

from parameterized import parameterized

from hvac.api.secrets_engines.transit import DEFAULT_MOUNT_POINT
from hvac.tests import utils


class TestTransit(utils.HvacIntegrationTestCase, TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestTransit, cls).setUpClass()

    def setUp(self):
        super(TestTransit, self).setUp()

    def tearDown(self):
        super(TestTransit, self).tearDown()


    @parameterized.expand([
        ('some_test',),
    ])
    def test_create_key(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_read_key(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_list_keys(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_delete_key(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_update_key_configuration(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_rotate_key(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_export_key(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_encrypt_data(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_decrypt_data(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_rewrap_data(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_generate_data_key(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_generate_random_bytes(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_hash_data(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_generate_hmac(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_sign_data(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_verify_signed_data(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_backup_key(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_restore_key(self, test_label):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    def test_trim_key(self, test_label):
        raise NotImplementedError

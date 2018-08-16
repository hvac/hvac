from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac.adapters import Request
from hvac.api.auth import Gcp
from hvac.api.auth.gcp import DEFAULT_MOUNT_POINT


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
    def test_configure(self, test_label, requests_mocker):
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
    def test_delete_config(self, test_label, requests_mocker):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_create_role(self, test_label, requests_mocker):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_edit_service_accounts_on_iam_role(self, test_label, requests_mocker):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_edit_labels_on_gce_role(self, test_label, requests_mocker):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_read_role(self, test_label, requests_mocker):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_list_roles(self, test_label, requests_mocker):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_delete_role(self, test_label, requests_mocker):
        raise NotImplementedError

    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_login(self, test_label, requests_mocker):
        raise NotImplementedError

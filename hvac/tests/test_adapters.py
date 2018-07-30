from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac import adapters


class TestRequest(TestCase):
    """Unit tests providing coverage for requests-related methods in the hvac Client class."""

    @parameterized.expand([
        ("standard Vault address", 'https://localhost:8200'),
        ("Vault address with route", 'https://example.com/vault'),
    ])
    @requests_mock.Mocker()
    def test_get(self, test_label, test_url, requests_mocker):
        test_path = 'v1/sys/health'
        expected_status_code = 200
        mock_url = '{0}/{1}'.format(test_url, test_path)
        requests_mocker.register_uri(
            method='GET',
            url=mock_url,
        )
        adapter = adapters.Request(base_uri=test_url)
        response = adapter.get(
            url='v1/sys/health',
        )
        self.assertEquals(
            first=expected_status_code,
            second=response.status_code,
        )

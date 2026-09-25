from unittest import TestCase

import requests_mock

from hvac.adapters import JSONAdapter
from hvac.api.system_backend import License


class TestLicense(TestCase):
    @requests_mock.Mocker()
    def test_read_license_status(self, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "data": {
                "autoloaded": {
                    "expiration_time": "2027-01-01T00:00:00Z",
                    "features": ["HSM", "Performance Replication"],
                    "license_id": "7d3a9c1e-0000-0000-0000-000000000000",
                    "start_time": "2026-01-01T00:00:00Z",
                    "termination_time": "2027-01-01T00:00:00Z",
                },
                "persisted_autoload": {
                    "expiration_time": "2027-01-01T00:00:00Z",
                    "features": ["HSM", "Performance Replication"],
                    "license_id": "7d3a9c1e-0000-0000-0000-000000000000",
                    "start_time": "2026-01-01T00:00:00Z",
                    "termination_time": "2027-01-01T00:00:00Z",
                },
            },
        }
        mock_url = "http://localhost:8200/v1/sys/license/status"
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        license = License(adapter=JSONAdapter())
        response = license.read_license_status()

        self.assertEqual(
            first=mock_response,
            second=response,
        )

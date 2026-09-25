from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac.adapters import JSONAdapter
from hvac.api.system_backend import Namespace


class TestNamespace(TestCase):
    @requests_mock.Mocker()
    def test_read_namespace(self, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "data": {
                "custom_metadata": {},
                "id": "ekiUn",
                "path": "testns/",
            },
        }
        mock_url = "http://localhost:8200/v1/sys/namespaces/testns"
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        namespace = Namespace(adapter=JSONAdapter())
        response = namespace.read_namespace(path="testns")

        self.assertEqual(
            first=mock_response,
            second=response,
        )

    @parameterized.expand(
        [
            ("with custom_metadata", {"env": "production"}),
            ("without custom_metadata", None),
        ]
    )
    @requests_mock.Mocker()
    def test_patch_namespace(self, test_label, custom_metadata, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "data": {
                "custom_metadata": custom_metadata or {},
                "id": "ekiUn",
                "path": "testns/",
            },
        }
        mock_url = "http://localhost:8200/v1/sys/namespaces/testns"
        requests_mocker.register_uri(
            method="PATCH",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        namespace = Namespace(adapter=JSONAdapter())
        response = namespace.patch_namespace(
            path="testns",
            custom_metadata=custom_metadata,
        )

        self.assertEqual(
            first=mock_response,
            second=response,
        )
        self.assertEqual(
            first="application/merge-patch+json",
            second=requests_mocker.last_request.headers["Content-Type"],
        )
        expected_body = {}
        if custom_metadata is not None:
            expected_body["custom_metadata"] = custom_metadata
        self.assertEqual(
            first=expected_body,
            second=requests_mocker.last_request.json(),
        )

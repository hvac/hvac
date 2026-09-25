from unittest import TestCase

import requests_mock

from hvac.adapters import JSONAdapter
from hvac.api.system_backend import ControlGroup


class TestControlGroup(TestCase):
    @requests_mock.Mocker()
    def test_authorize_control_group(self, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "data": {
                "approved": True,
            },
        }
        mock_url = "http://localhost:8200/v1/sys/control-group/authorize"
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        control_group = ControlGroup(adapter=JSONAdapter())
        response = control_group.authorize_control_group(accessor="test-accessor")

        self.assertEqual(
            first=mock_response,
            second=response,
        )
        self.assertEqual(
            first={"accessor": "test-accessor"},
            second=requests_mocker.last_request.json(),
        )

    @requests_mock.Mocker()
    def test_check_control_group_request(self, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "data": {
                "approved": False,
                "request_path": "secret/foo",
                "request_entity": {
                    "id": "c8b6b6e1-0000-0000-0000-000000000000",
                    "name": "requester",
                },
                "authorizations": [],
            },
        }
        mock_url = "http://localhost:8200/v1/sys/control-group/request"
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        control_group = ControlGroup(adapter=JSONAdapter())
        response = control_group.check_control_group_request(accessor="test-accessor")

        self.assertEqual(
            first=mock_response,
            second=response,
        )
        self.assertEqual(
            first={"accessor": "test-accessor"},
            second=requests_mocker.last_request.json(),
        )

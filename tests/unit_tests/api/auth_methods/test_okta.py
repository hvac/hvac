import logging
from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac.adapters import JSONAdapter
from hvac.api.auth_methods import Okta


class TestOkta(TestCase):
    TEST_MOUNT_POINT = "okta-test"
    TEST_USERNAME = "hvac-person"

    @parameterized.expand(
        [
            (
                "success",
                dict(),
                None,
            ),
        ]
    )
    @requests_mock.Mocker()
    def test_login(self, label, test_params, raises, requests_mocker):
        test_policies = [
            "default",
        ]
        expected_status_code = 200
        mock_url = (
            "http://localhost:8200/v1/auth/{mount_point}/login/{username}".format(
                mount_point=self.TEST_MOUNT_POINT,
                username=self.TEST_USERNAME,
            )
        )
        mock_response = {
            "lease_id": "",
            "data": None,
            "warnings": None,
            "auth": {
                "client_token": "64d2a8f2-2a2f-5688-102b-e6088b76e344",
                "accessor": "18bb8f89-826a-56ee-c65b-1736dc5ea27d",
                "policies": ["default"],
                "metadata": {"username": self.TEST_USERNAME, "policies": "default"},
            },
            "lease_duration": 7200,
            "renewable": True,
        }
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        okta = Okta(adapter=JSONAdapter())
        if raises is not None:
            with self.assertRaises(raises):
                okta.login(
                    username=self.TEST_USERNAME,
                    password="badpassword",
                    mount_point=self.TEST_MOUNT_POINT,
                    **test_params
                )
        else:
            login_response = okta.login(
                username=self.TEST_USERNAME,
                password="badpassword",
                mount_point=self.TEST_MOUNT_POINT,
                **test_params
            )
            logging.debug("login_response: %s" % login_response)
            self.assertEqual(
                first=login_response["auth"]["policies"],
                second=test_policies,
            )

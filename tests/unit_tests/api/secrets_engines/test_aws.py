#!/usr/bin/env python
import logging
from unittest import TestCase

import requests_mock
from parameterized import parameterized, param

from hvac.adapters import JSONAdapter
from hvac.api.secrets_engines import Aws
from hvac.api.secrets_engines.aws import DEFAULT_MOUNT_POINT
from hvac.exceptions import ParamValidationError


class TestAws(TestCase):
    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_rotate_root_iam_credentials(
        self, test_label, mount_point=DEFAULT_MOUNT_POINT
    ):
        expected_status_code = 200
        mock_response = {"data": {"access_key": "AKIA..."}}
        aws = Aws(adapter=JSONAdapter())
        mock_url = "http://localhost:8200/v1/{mount_point}/config/rotate-root".format(
            mount_point=mount_point,
        )
        logging.debug("Mocking URL: %s" % mock_url)
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="POST",
                url=mock_url,
                status_code=expected_status_code,
                json=mock_response,
            )
            rotate_root_response = aws.rotate_root_iam_credentials(
                mount_point=mount_point,
            )
        logging.debug("rotate_root_response: %s" % rotate_root_response)
        self.assertEqual(
            first=mock_response,
            second=rotate_root_response,
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "invalid endpoint",
                endpoint="cats",
                raises=ParamValidationError,
                exception_msg="cats",
            ),
        ]
    )
    def test_generate_credentials(
        self,
        test_label,
        role_name="hvac-test-role",
        mount_point=DEFAULT_MOUNT_POINT,
        endpoint="creds",
        raises=None,
        exception_msg="",
    ):
        expected_status_code = 200
        mock_response = {
            "data": {
                "access_key": "AKIA...",
                "secret_key": "xlCs...",
                "security_token": None,
            }
        }
        mock_url = "http://localhost:8200/v1/{mount_point}/creds/{role_name}".format(
            mount_point=mount_point,
            role_name=role_name,
        )
        logging.debug("Mocking URL: %s" % mock_url)
        aws = Aws(adapter=JSONAdapter())
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="GET",
                url=mock_url,
                status_code=expected_status_code,
                json=mock_response,
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    aws.generate_credentials(
                        name=role_name,
                        endpoint=endpoint,
                        mount_point=mount_point,
                    )
                self.assertIn(
                    member=exception_msg,
                    container=str(cm.exception),
                )
            else:
                gen_creds_response = aws.generate_credentials(
                    name=role_name,
                    endpoint=endpoint,
                    mount_point=mount_point,
                )
                logging.debug("gen_creds_response: %s" % gen_creds_response)
                self.assertEqual(
                    first=mock_response,
                    second=gen_creds_response,
                )

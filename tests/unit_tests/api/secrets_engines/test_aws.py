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

    @parameterized.expand(
        [
            param(
                "required params only",
                expected_body={"username": "hvac-user", "rotation_period": "24h"},
            ),
            param(
                "integer rotation period",
                rotation_period=86400,
                expected_body={"username": "hvac-user", "rotation_period": 86400},
            ),
            param(
                "cross-account params",
                assume_role_arn="arn:aws:iam::123456789012:role/vault",
                assume_role_session_name="hvac-session",
                external_id="hvac-external-id",
                expected_body={
                    "username": "hvac-user",
                    "rotation_period": "24h",
                    "assume_role_arn": "arn:aws:iam::123456789012:role/vault",
                    "assume_role_session_name": "hvac-session",
                    "external_id": "hvac-external-id",
                },
            ),
            param(
                "custom mount point",
                mount_point="other-aws",
                expected_body={"username": "hvac-user", "rotation_period": "24h"},
            ),
        ]
    )
    def test_create_or_update_static_role(
        self,
        test_label,
        expected_body,
        rotation_period="24h",
        assume_role_arn=None,
        assume_role_session_name=None,
        external_id=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        mock_response = {
            "data": {
                "name": "hvac-static-role",
                "username": "hvac-user",
                "rotation_period": 86400,
            }
        }
        mock_url = "http://localhost:8200/v1/{mount_point}/static-roles/hvac-static-role".format(
            mount_point=mount_point,
        )
        aws = Aws(adapter=JSONAdapter())
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="POST",
                url=mock_url,
                status_code=200,
                json=mock_response,
            )
            response = aws.create_or_update_static_role(
                name="hvac-static-role",
                username="hvac-user",
                rotation_period=rotation_period,
                assume_role_arn=assume_role_arn,
                assume_role_session_name=assume_role_session_name,
                external_id=external_id,
                mount_point=mount_point,
            )
            self.assertEqual(
                first=expected_body,
                second=requests_mocker.last_request.json(),
            )
        self.assertEqual(
            first=mock_response,
            second=response,
        )

    @parameterized.expand(
        [
            param("default mount point"),
            param("custom mount point", mount_point="other-aws"),
        ]
    )
    def test_read_static_role(self, test_label, mount_point=DEFAULT_MOUNT_POINT):
        mock_response = {
            "data": {
                "name": "hvac-static-role",
                "username": "hvac-user",
                "rotation_period": 86400,
            }
        }
        mock_url = "http://localhost:8200/v1/{mount_point}/static-roles/hvac-static-role".format(
            mount_point=mount_point,
        )
        aws = Aws(adapter=JSONAdapter())
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="GET",
                url=mock_url,
                status_code=200,
                json=mock_response,
            )
            response = aws.read_static_role(
                name="hvac-static-role",
                mount_point=mount_point,
            )
        self.assertEqual(
            first=mock_response,
            second=response,
        )

    @parameterized.expand(
        [
            param("default mount point"),
            param("custom mount point", mount_point="other-aws"),
        ]
    )
    def test_list_static_roles(self, test_label, mount_point=DEFAULT_MOUNT_POINT):
        mock_response = {"data": {"keys": ["hvac-static-role"]}}
        mock_url = "http://localhost:8200/v1/{mount_point}/static-roles".format(
            mount_point=mount_point,
        )
        aws = Aws(adapter=JSONAdapter())
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="LIST",
                url=mock_url,
                status_code=200,
                json=mock_response,
            )
            response = aws.list_static_roles(
                mount_point=mount_point,
            )
        self.assertEqual(
            first=mock_response,
            second=response,
        )

    @parameterized.expand(
        [
            param("default mount point"),
            param("custom mount point", mount_point="other-aws"),
        ]
    )
    def test_delete_static_role(self, test_label, mount_point=DEFAULT_MOUNT_POINT):
        expected_status_code = 204
        mock_url = "http://localhost:8200/v1/{mount_point}/static-roles/hvac-static-role".format(
            mount_point=mount_point,
        )
        aws = Aws(adapter=JSONAdapter())
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="DELETE",
                url=mock_url,
                status_code=expected_status_code,
            )
            response = aws.delete_static_role(
                name="hvac-static-role",
                mount_point=mount_point,
            )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            param("default mount point"),
            param("custom mount point", mount_point="other-aws"),
        ]
    )
    def test_get_static_credentials(self, test_label, mount_point=DEFAULT_MOUNT_POINT):
        mock_response = {
            "data": {
                "access_key": "AKIA...",
                "secret_key": "xlCs...",
                "expiration": "2026-11-14T10:00:00Z",
            }
        }
        mock_url = "http://localhost:8200/v1/{mount_point}/static-creds/hvac-static-role".format(
            mount_point=mount_point,
        )
        aws = Aws(adapter=JSONAdapter())
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="GET",
                url=mock_url,
                status_code=200,
                json=mock_response,
            )
            response = aws.get_static_credentials(
                name="hvac-static-role",
                mount_point=mount_point,
            )
        self.assertEqual(
            first=mock_response,
            second=response,
        )

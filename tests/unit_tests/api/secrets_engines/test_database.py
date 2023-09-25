import logging
import requests_mock
from unittest import TestCase

from hvac.api.secrets_engines.database import Database
from hvac.api.secrets_engines.database import DEFAULT_MOUNT_POINT
from hvac.adapters import JSONAdapter


class TestDatabase(TestCase):
    def setUp(self):
        self.database = Database(adapter=JSONAdapter())
        self.expected_status_code = 200

    def mock_request(self, method, mock_url, mock_response):
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=self.expected_status_code,
                json=mock_response,
            )
            return requests_mocker

    def test_configure(self):
        name = "test_db"
        plugin_name = "test_plugin"
        verify_connection = None
        allowed_roles = None
        root_rotation_statements = None
        mount_point = DEFAULT_MOUNT_POINT

        mock_url = f"http://localhost:8200/v1/{mount_point}/config/{name}"
        mock_response = {"status_code": 204}  # no response other than status code
        expected_status_code = 204

        with self.mock_request("POST", mock_url, mock_response):
            configure_response = self.database.configure(
                name=name,
                plugin_name=plugin_name,
                verify_connection=verify_connection,
                allowed_roles=allowed_roles,
                root_rotation_statements=root_rotation_statements,
                mount_point=mount_point,
            )
        logging.debug("configure_response: %s" % configure_response)

        self.assertEqual(configure_response["status_code"], expected_status_code)

    def test_rotate_root_credentials(self):
        name = "test_db"
        mount_point = DEFAULT_MOUNT_POINT

        mock_url = f"http://localhost:8200/v1/{mount_point}/rotate-root/{name}"
        mock_response = {"status_code": 204}  # no response other than status code
        expected_status_code = 204

        with self.mock_request("POST", mock_url, mock_response):
            rotate_root_credentials_response = self.database.rotate_root_credentials(
                name=name, mount_point=mount_point
            )
        logging.debug(
            "rotate_root_credentials_response: %s" % rotate_root_credentials_response
        )
        self.assertEqual(
            rotate_root_credentials_response["status_code"], expected_status_code
        )

    def test_rotate_static_role_credentials(self):
        name = "test_role"
        mount_point = DEFAULT_MOUNT_POINT

        mock_url = f"http://localhost:8200/v1/{mount_point}/rotate-role/{name}"
        mock_response = {
            "data": {"last_vault_rotation": "2023-09-25T19:02:38.347994635Z"}
        }

        with self.mock_request("POST", mock_url, mock_response):
            rotate_static_credentials_response = (
                self.database.rotate_static_role_credentials(
                    name=name, mount_point=mount_point
                )
            )
        logging.debug(
            "rotate_static_credentials_response: %s"
            % rotate_static_credentials_response
        )
        self.assertEqual(rotate_static_credentials_response, mock_response)

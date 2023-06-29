from textwrap import dedent
from unittest import TestCase

import requests_mock
from parameterized import parameterized, param

from hvac.adapters import JSONAdapter
from hvac.api.secrets_engines import Gcp
from hvac.exceptions import (
    ParamValidationError,
    InvalidRequest,
    InvalidPath,
    UnexpectedError,
    InternalServerError,
)

TEST_MOUNT_POINT = "gcp-test"
TEST_ROLESET_NAME = "hvac-roleset"
TEST_SERVICE_ACCOUNT_ID = "test-hvac-sa"
TEST_PROJECT_ID = "test-hvac"
TEST_STATIC_ACCOUNT_NAME = "hvac-static-account"
TEST_IMPERSONATED_ACCOUNT_NAME = "hvac-impersonated-account"
TEST_SERVICE_ACCOUNT_EMAIL = (
    f"{TEST_SERVICE_ACCOUNT_ID}@{TEST_PROJECT_ID}.iam.gserviceaccount.com"
)
DEFAULT_CREDENTIALS = dedent(
    """
    {
        "project_id": "test-hvac-project-not-a-real-project",
        "private_key_id": "3900c1e6f6720d770a6af25710cad56696272f8d",
    }
    """
)
DEFAULT_BINDINGS = dedent(
    """
    resource "//cloudresourcemanager.googleapis.com/projects/mygcpproject" {
      roles = [
        "roles/viewer"
      ],
    }
    """
)
DEFAULT_TOKEN_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class TestGcp(TestCase):
    def setUp(self):
        self._json_adapter = Gcp(adapter=JSONAdapter())

    @parameterized.expand(
        [
            param(method="POST", expected_status_code=204),
            param(
                method="POST",
                expected_status_code=400,
                raises=InvalidRequest,
                expected_response={"errors": ["error parsing JSON"]},
            ),
        ]
    )
    def test_configure(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/config".format(
            mount_point=TEST_MOUNT_POINT,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                invalid_json = {"project_id": None}

                with self.assertRaises(raises) as cm:

                    self._json_adapter.configure(
                        credentials=invalid_json,
                        ttl=3600,
                        max_ttl=14400,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.configure(
                    credentials=DEFAULT_CREDENTIALS,
                    ttl=3600,
                    max_ttl=14400,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)

    @parameterized.expand(
        [
            param(
                method="POST",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "private_key_id": "bb9b47e33693847c8281a959c4286eb848be909c"
                    }
                },
            ),
            param(
                method="POST",
                expected_status_code=404,
                raises=InvalidPath,
                expected_response={"errors": ["no handler for route"]},
            ),
            param(
                method="POST",
                expected_status_code=500,
                raises=InternalServerError,
                expected_response={
                    "errors": ["1 error occurred: failed to create new key"]
                },
            ),
        ]
    )
    def test_rotate_root_credentials(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/config/rotate-root".format(
            mount_point=TEST_MOUNT_POINT,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.rotate_root_credentials(
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.rotate_root_credentials(
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(
                method="GET",
                expected_status_code=200,
                expected_response={"data": {"max_ttl": 0, "ttl": 0}},
            ),
            param(
                method="GET",
                expected_status_code=404,
                raises=InvalidPath,
                expected_response={"errors": ["no handler for route"]},
            ),
        ]
    )
    def test_read_config(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/config".format(
            mount_point=TEST_MOUNT_POINT,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.read_config(
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(expected_response, cm.exception.json)
            else:
                resp = self._json_adapter.read_config(
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(method="POST", expected_status_code=204, secret_type="access_token"),
            param(
                method="POST",
                expected_status_code=204,
                secret_type="service_account_key",
            ),
            param(
                method="POST",
                expected_status_code=204,
                secret_type="invalid_secret_type",
                raises=ParamValidationError,
            ),
        ]
    )
    def test_create_or_update_roleset(
        self,
        method,
        expected_status_code,
        secret_type,
        raises=None,
        expected_response=None,
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/roleset/{name}".format(
            mount_point=TEST_MOUNT_POINT,
            name=TEST_ROLESET_NAME,
        )

        token_scopes = DEFAULT_TOKEN_SCOPES if secret_type == "access_token" else None

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.create_or_update_roleset(
                        name=TEST_ROLESET_NAME,
                        project=TEST_PROJECT_ID,
                        bindings=DEFAULT_BINDINGS,
                        secret_type=secret_type,
                        token_scopes=token_scopes,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertIn(
                    member="unsupported secret_type argument provided",
                    container=str(cm.exception),
                )
            else:
                resp = self._json_adapter.create_or_update_roleset(
                    name=TEST_ROLESET_NAME,
                    project=TEST_PROJECT_ID,
                    bindings=DEFAULT_BINDINGS,
                    secret_type=secret_type,
                    token_scopes=token_scopes,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)

    @parameterized.expand(
        [
            param(method="POST", expected_status_code=204),
            param(method="POST", expected_status_code=400, raises=InvalidRequest),
            param(method="POST", expected_status_code=405, raises=UnexpectedError),
        ]
    )
    def test_rotate_roleset_account(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/roleset/{name}/rotate".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_ROLESET_NAME,
            )
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.rotate_roleset_account(
                        name=TEST_ROLESET_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertIn(member=mock_url, container=str(cm.exception))
            else:
                resp = self._json_adapter.rotate_roleset_account(
                    name=TEST_ROLESET_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)
                self.assertTrue(len(resp.content) == 0)

    @parameterized.expand(
        [
            param(method="POST", expected_status_code=204),
            param(method="POST", expected_status_code=400, raises=InvalidRequest),
            param(method="POST", expected_status_code=405, raises=UnexpectedError),
        ]
    )
    def test_rotate_roleset_account_key(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/roleset/{name}/rotate-key".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_ROLESET_NAME,
            )
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.rotate_roleset_account_key(
                        name=TEST_ROLESET_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertIn(member=mock_url, container=str(cm.exception))
            else:
                resp = self._json_adapter.rotate_roleset_account_key(
                    name=TEST_ROLESET_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)
                self.assertTrue(len(resp.content) == 0)

    @parameterized.expand(
        [
            param(
                method="GET",
                expected_status_code=200,
                secret_type="access_token",
                expected_response={
                    "data": {
                        "secret_type": "access_token",
                        "service_account_email": TEST_SERVICE_ACCOUNT_EMAIL,
                        "service_account_project": TEST_PROJECT_ID,
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=200,
                secret_type="service_account_key",
                expected_response={
                    "data": {
                        "secret_type": "service_account_key",
                        "service_account_email": TEST_SERVICE_ACCOUNT_EMAIL,
                        "service_account_project": TEST_PROJECT_ID,
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=404,
                secret_type="access_token",
                raises=InvalidPath,
            ),
            param(
                method="GET",
                expected_status_code=405,
                secret_type="service_account_key",
                raises=UnexpectedError,
            ),
        ]
    )
    def test_read_roleset(
        self,
        method,
        expected_status_code,
        secret_type,
        raises=None,
        expected_response=None,
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/roleset/{name}".format(
            mount_point=TEST_MOUNT_POINT,
            name=TEST_ROLESET_NAME,
        )

        if expected_response is not None and secret_type == "access_token":
            expected_response["data"]["token_scopes"] = DEFAULT_TOKEN_SCOPES

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.read_roleset(
                        name=TEST_ROLESET_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertIn(member=mock_url, container=str(cm.exception))
            else:
                resp = self._json_adapter.read_roleset(
                    name=TEST_ROLESET_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(
                method="LIST",
                expected_status_code=200,
                expected_response={"data": {"keys": ["roleset-01", "roleset-02"]}},
            ),
            param(method="LIST", expected_status_code=404, raises=InvalidPath),
            param(method="LIST", expected_status_code=405, raises=UnexpectedError),
        ]
    )
    def test_list_rolesets(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/rolesets".format(
            mount_point=TEST_MOUNT_POINT,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.list_rolesets(
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertIn(member=mock_url, container=str(cm.exception))
            else:
                resp = self._json_adapter.list_rolesets(
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(method="DELETE", expected_status_code=204),
            param(method="DELETE", expected_status_code=404, raises=InvalidPath),
            param(method="DELETE", expected_status_code=405, raises=UnexpectedError),
        ]
    )
    def test_delete_roleset(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/roleset/{name}".format(
            mount_point=TEST_MOUNT_POINT,
            name=TEST_ROLESET_NAME,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.delete_roleset(
                        name=TEST_ROLESET_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertIn(member=mock_url, container=str(cm.exception))
            else:
                resp = self._json_adapter.delete_roleset(
                    name=TEST_ROLESET_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)
                self.assertTrue(len(resp.content) == 0)

    @parameterized.expand(
        [
            param(
                method="GET",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "expires_at_seconds": 1679109162,
                        "token": "ya29.c.b0Aaekm1Le-n2NCqrzZjdMtjpbgRji2yhiJkO...",
                        "token_ttl": 3598,
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=400,
                raises=InvalidRequest,
                expected_response={
                    "errors": ["role set 'missing-roleset' does not exists"]
                },
            ),
        ]
    )
    def test_generate_oauth2_access_token(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/token/{roleset}".format(
            mount_point=TEST_MOUNT_POINT,
            roleset=TEST_ROLESET_NAME,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.generate_oauth2_access_token(
                        roleset=TEST_ROLESET_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertIn(member=mock_url, container=str(cm.exception))
            else:
                resp = self._json_adapter.generate_oauth2_access_token(
                    roleset=TEST_ROLESET_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(
                method="GET",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "key_algorithm": "KEY_ALG_RSA_2048",
                        "key_type": "TYPE_GOOGLE_CREDENTIALS_FILE",
                        "private_key_data": "ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgIn...",
                    }
                },
            ),
            param(
                method="POST",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "key_algorithm": "KEY_ALG_RSA_1024",
                        "key_type": "TYPE_GOOGLE_CREDENTIALS_FILE",
                        "private_key_data": "ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgIn...",
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=400,
                raises=InvalidRequest,
                expected_response={
                    "errors": ["role set 'missing-roleset' does not exists"]
                },
            ),
        ]
    )
    def test_generate_service_account_key(
        self,
        method,
        expected_status_code,
        raises=None,
        expected_response=None,
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/key/{roleset}".format(
            mount_point=TEST_MOUNT_POINT,
            roleset=TEST_ROLESET_NAME,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.generate_service_account_key(
                        roleset=TEST_ROLESET_NAME,
                        mount_point=TEST_MOUNT_POINT,
                        method=method,
                    )

                self.assertIn(member=mock_url, container=str(cm.exception))
            else:
                resp = self._json_adapter.generate_service_account_key(
                    roleset=TEST_ROLESET_NAME,
                    mount_point=TEST_MOUNT_POINT,
                    method=method,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(method="POST", expected_status_code=204, secret_type="access_token"),
            param(
                method="POST",
                expected_status_code=204,
                secret_type="service_account_key",
            ),
            param(
                method="POST",
                expected_status_code=204,
                secret_type="invalid_secret_type",
                raises=ParamValidationError,
            ),
        ]
    )
    def test_create_or_update_static_account(
        self,
        method,
        expected_status_code,
        secret_type,
        raises=None,
        expected_response=None,
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/static-account/{name}".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_STATIC_ACCOUNT_NAME,
            )
        )

        token_scopes = DEFAULT_TOKEN_SCOPES if secret_type == "access_token" else None

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.create_or_update_static_account(
                        name=TEST_STATIC_ACCOUNT_NAME,
                        service_account_email=TEST_SERVICE_ACCOUNT_EMAIL,
                        bindings=DEFAULT_BINDINGS,
                        secret_type=secret_type,
                        token_scopes=token_scopes,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertIn(
                    member="unsupported secret_type argument provided",
                    container=str(cm.exception),
                )
            else:
                resp = self._json_adapter.create_or_update_static_account(
                    name=TEST_STATIC_ACCOUNT_NAME,
                    service_account_email=TEST_SERVICE_ACCOUNT_EMAIL,
                    bindings=DEFAULT_BINDINGS,
                    secret_type=secret_type,
                    token_scopes=token_scopes,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)
                self.assertTrue(len(resp.content) == 0)

    @parameterized.expand(
        [
            param(method="POST", expected_status_code=204),
            param(method="POST", expected_status_code=400, raises=InvalidRequest),
            param(
                method="POST",
                expected_status_code=405,
                raises=UnexpectedError,
                expected_response={
                    "errors": ["cannot rotate key for non-access-token static account"]
                },
            ),
        ]
    )
    def test_rotate_static_account_key(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/static-account/{name}/rotate-key".format(
            mount_point=TEST_MOUNT_POINT,
            name=TEST_STATIC_ACCOUNT_NAME,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.rotate_static_account_key(
                        name=TEST_STATIC_ACCOUNT_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.rotate_static_account_key(
                    name=TEST_STATIC_ACCOUNT_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)
                self.assertTrue(len(resp.content) == 0)

    @parameterized.expand(
        [
            param(
                method="GET",
                expected_status_code=200,
                secret_type="access_token",
                expected_response={
                    "data": {
                        "secret_type": "access_token",
                        "service_account_email": TEST_SERVICE_ACCOUNT_EMAIL,
                        "service_account_project": TEST_PROJECT_ID,
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=200,
                secret_type="service_account_key",
                expected_response={
                    "data": {
                        "secret_type": "service_account_key",
                        "service_account_email": TEST_SERVICE_ACCOUNT_EMAIL,
                        "service_account_project": TEST_PROJECT_ID,
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=404,
                secret_type="access_token",
                raises=InvalidPath,
            ),
            param(
                method="GET",
                expected_status_code=405,
                secret_type="service_account_key",
                raises=UnexpectedError,
            ),
        ]
    )
    def test_read_static_account(
        self,
        method,
        expected_status_code,
        secret_type,
        raises=None,
        expected_response=None,
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/static-account/{name}".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_STATIC_ACCOUNT_NAME,
            )
        )

        if expected_response is not None and secret_type == "access_token":
            expected_response["data"]["token_scopes"] = DEFAULT_TOKEN_SCOPES

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.read_static_account(
                        name=TEST_STATIC_ACCOUNT_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.read_static_account(
                    name=TEST_STATIC_ACCOUNT_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(
                method="LIST",
                expected_status_code=200,
                expected_response={
                    "data": {"keys": ["static-account-01", "static-account-02"]}
                },
            ),
            param(method="LIST", expected_status_code=404, raises=InvalidPath),
            param(method="LIST", expected_status_code=405, raises=UnexpectedError),
        ]
    )
    def test_list_static_accounts(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/static-accounts".format(
            mount_point=TEST_MOUNT_POINT,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.list_static_accounts(
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.list_static_accounts(
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(method="DELETE", expected_status_code=204),
            param(method="DELETE", expected_status_code=404, raises=InvalidPath),
            param(method="DELETE", expected_status_code=405, raises=UnexpectedError),
        ]
    )
    def test_delete_static_account(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/static-account/{name}".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_STATIC_ACCOUNT_NAME,
            )
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.delete_static_account(
                        name=TEST_STATIC_ACCOUNT_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.delete_static_account(
                    name=TEST_STATIC_ACCOUNT_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)
                self.assertTrue(len(resp.content) == 0)

    @parameterized.expand(
        [
            param(
                method="GET",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "expires_at_seconds": 1679109162,
                        "token": "ya29.c.b0Aaekm1Le-n2NCqrzZjdMtjpbgRji2yhiJkO...",
                        "token_ttl": 3598,
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=400,
                raises=InvalidRequest,
                expected_response={
                    "errors": ['static account "missing-account" does not exists'],
                },
            ),
        ]
    )
    def test_generate_static_account_oauth2_access_token(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/static-account/{name}/token".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_STATIC_ACCOUNT_NAME,
            )
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.generate_static_account_oauth2_access_token(
                        name=TEST_STATIC_ACCOUNT_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.generate_static_account_oauth2_access_token(
                    name=TEST_STATIC_ACCOUNT_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(
                method="GET",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "key_algorithm": "KEY_ALG_RSA_2048",
                        "key_type": "TYPE_GOOGLE_CREDENTIALS_FILE",
                        "private_key_data": "ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgIn...",
                    }
                },
            ),
            param(
                method="POST",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "key_algorithm": "KEY_ALG_RSA_1024",
                        "key_type": "TYPE_GOOGLE_CREDENTIALS_FILE",
                        "private_key_data": "ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgIn...",
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=400,
                raises=InvalidRequest,
                expected_response={
                    "errors": ['static account "missing-account" does not exists'],
                },
            ),
        ]
    )
    def test_generate_static_account_service_account_key(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/static-account/{name}/key".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_STATIC_ACCOUNT_NAME,
            )
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.generate_static_account_service_account_key(
                        name=TEST_STATIC_ACCOUNT_NAME,
                        mount_point=TEST_MOUNT_POINT,
                        method=method,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.generate_static_account_service_account_key(
                    name=TEST_STATIC_ACCOUNT_NAME,
                    mount_point=TEST_MOUNT_POINT,
                    method=method,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(method="POST", expected_status_code=204, ttl="3h"),
            param(
                method="POST",
                expected_status_code=400,
                ttl="invalid",
                raises=InvalidRequest,
                expected_response={
                    "errors": ['error converting input invalid for field "ttl"']
                },
            ),
        ]
    )
    def test_create_or_update_impersonated_account(
        self,
        method,
        expected_status_code,
        ttl,
        raises=None,
        expected_response=None,
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/impersonated-account/{name}".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_IMPERSONATED_ACCOUNT_NAME,
            )
        )

        token_scopes = DEFAULT_TOKEN_SCOPES

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.create_or_update_impersonated_account(
                        name=TEST_IMPERSONATED_ACCOUNT_NAME,
                        service_account_email=TEST_SERVICE_ACCOUNT_EMAIL,
                        token_scopes=token_scopes,
                        ttl=ttl,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertIn(
                    member='error converting input invalid for field "ttl"',
                    container=str(cm.exception),
                )
            else:
                resp = self._json_adapter.create_or_update_impersonated_account(
                    name=TEST_IMPERSONATED_ACCOUNT_NAME,
                    service_account_email=TEST_SERVICE_ACCOUNT_EMAIL,
                    token_scopes=token_scopes,
                    ttl=ttl,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)
                self.assertTrue(len(resp.content) == 0)

    @parameterized.expand(
        [
            param(
                method="GET",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "service_account_email": TEST_SERVICE_ACCOUNT_EMAIL,
                        "service_account_project": TEST_PROJECT_ID,
                        "token_scopes": DEFAULT_TOKEN_SCOPES,
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=404,
                raises=InvalidPath,
            ),
        ]
    )
    def test_read_impersonated_account(
        self,
        method,
        expected_status_code,
        raises=None,
        expected_response=None,
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/impersonated-account/{name}".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_IMPERSONATED_ACCOUNT_NAME,
            )
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.read_impersonated_account(
                        name=TEST_IMPERSONATED_ACCOUNT_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.read_impersonated_account(
                    name=TEST_IMPERSONATED_ACCOUNT_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(
                method="LIST",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "keys": ["impersonated-account-01", "impersonated-account-02"]
                    }
                },
            ),
            param(method="LIST", expected_status_code=404, raises=InvalidPath),
            param(method="LIST", expected_status_code=405, raises=UnexpectedError),
        ]
    )
    def test_list_impersonated_accounts(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/impersonated-accounts".format(
                mount_point=TEST_MOUNT_POINT,
            )
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.list_impersonated_accounts(
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.list_impersonated_accounts(
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

    @parameterized.expand(
        [
            param(method="DELETE", expected_status_code=204),
            param(method="DELETE", expected_status_code=404, raises=InvalidPath),
            param(method="DELETE", expected_status_code=405, raises=UnexpectedError),
        ]
    )
    def test_delete_impersonated_account(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = (
            "http://localhost:8200/v1/{mount_point}/impersonated-account/{name}".format(
                mount_point=TEST_MOUNT_POINT,
                name=TEST_IMPERSONATED_ACCOUNT_NAME,
            )
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.delete_impersonated_account(
                        name=TEST_IMPERSONATED_ACCOUNT_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.delete_impersonated_account(
                    name=TEST_IMPERSONATED_ACCOUNT_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp.status_code, expected_status_code)
                self.assertTrue(len(resp.content) == 0)

    @parameterized.expand(
        [
            param(
                method="GET",
                expected_status_code=200,
                expected_response={
                    "data": {
                        "expires_at_seconds": 1679109162,
                        "token": "ya29.c.b0Aaekm1Le-n2NCqrzZjdMtjpbgRji2yhiJkO...",
                        "token_ttl": 3598,
                    }
                },
            ),
            param(
                method="GET",
                expected_status_code=400,
                raises=InvalidRequest,
                expected_response={
                    "errors": [
                        'impersonated account "missing-account" does not exists'
                    ],
                },
            ),
        ]
    )
    def test_generate_impersonated_account_oauth2_access_token(
        self, method, expected_status_code, raises=None, expected_response=None
    ):
        mock_url = "http://localhost:8200/v1/{mount_point}/impersonated-account/{name}/token".format(
            mount_point=TEST_MOUNT_POINT,
            name=TEST_IMPERSONATED_ACCOUNT_NAME,
        )

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method=method,
                url=mock_url,
                status_code=expected_status_code,
                json=expected_response,
                headers={"Content-Type": "application/json"},
            )

            if raises:
                with self.assertRaises(raises) as cm:
                    self._json_adapter.generate_impersonated_account_oauth2_access_token(
                        name=TEST_IMPERSONATED_ACCOUNT_NAME,
                        mount_point=TEST_MOUNT_POINT,
                    )

                self.assertEqual(cm.exception.json, expected_response)
            else:
                resp = self._json_adapter.generate_impersonated_account_oauth2_access_token(
                    name=TEST_IMPERSONATED_ACCOUNT_NAME,
                    mount_point=TEST_MOUNT_POINT,
                )

                self.assertEqual(resp, expected_response)

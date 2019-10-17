import logging
from textwrap import dedent
from unittest import TestCase

import requests_mock
from parameterized import parameterized, param

from hvac.adapters import JSONAdapter
from hvac.api.secrets_engines import Gcp


class TestGcp(TestCase):
    TEST_MOUNT_POINT = 'gcp-test'
    TEST_ROLESET_NAME = 'hvac-roleset'
    TEST_PROJECT_ID = 'test-hvac'

    @parameterized.expand([
        param(
            'success',
        ),
    ])
    def test_create_or_update_roleset(self, label, secret_type='access_token', raises=False, exception_message=''):

        bindings = {
            'resource': {
                "//cloudresourcemanager.googleapis.com/projects/{project}".format(project=self.TEST_PROJECT_ID): {
                    "roles": ['roles/viewer'],
                },
            },
        }
        bindings = """
            resource "//cloudresourcemanager.googleapis.com/project/{project}" {
              roles = [
                "roles/viewer"
              ],
            }
        """
        bindings = dedent(bindings)
        token_scopes = None
        if secret_type == 'access_token':
            token_scopes = [
                'https://www.googleapis.com/auth/cloud-platform',
                'https://www.googleapis.com/auth/bigquery',
            ]

        gcp = Gcp(adapter=JSONAdapter())
        mock_url = 'http://localhost:8200/v1/{mount_point}/roleset/{name}'.format(
            mount_point=self.TEST_MOUNT_POINT,
            name=self.TEST_ROLESET_NAME,
        )
        expected_status_code = 204

        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method='POST',
                url=mock_url,
                status_code=expected_status_code,
            )
            if raises:
                with self.assertRaises(raises) as cm:
                    gcp.create_or_update_roleset(
                        name=self.TEST_ROLESET_NAME,
                        project=self.TEST_PROJECT_ID,
                        bindings=bindings,
                        secret_type=secret_type,
                        token_scopes=token_scopes,
                        mount_point=self.TEST_MOUNT_POINT,
                    )
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
            else:
                create_or_update_response = gcp.create_or_update_roleset(
                    name=self.TEST_ROLESET_NAME,
                    project=self.TEST_PROJECT_ID,
                    bindings=bindings,
                    secret_type=secret_type,
                    token_scopes=token_scopes,
                    mount_point=self.TEST_MOUNT_POINT,
                )
                logging.debug('configure_response: %s' % create_or_update_response)
                self.assertEqual(
                    first=create_or_update_response.status_code,
                    second=204,
                )

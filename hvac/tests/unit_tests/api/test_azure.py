from unittest import TestCase

from mock import MagicMock
from parameterized import parameterized, param

from hvac.api.azure import Azure
from hvac.api.auth import azure as azure_auth_method
from hvac.api.secrets_engines import azure as azure_secret_engine
from hvac.tests import utils


class TestAzure(utils.HvacIntegrationTestCase, TestCase):

    def test_auth_property(self):
        mock_adapter = MagicMock()
        azure = Azure(adapter=mock_adapter)
        self.assertIsInstance(
            obj=azure.auth,
            cls=azure_auth_method.Azure,
        )

    def test_secret_property(self):
        mock_adapter = MagicMock()
        azure = Azure(adapter=mock_adapter)
        self.assertIsInstance(
            obj=azure.secret,
            cls=azure_secret_engine.Azure,
        )

    @parameterized.expand([
        param(
            'auth method method',
            method='configure',
            expected_property='auth',
        ),
        param(
            'secret engine method',
            method='generate_credentials',
            expected_property='secret',
        ),
    ])
    def test_getattr(self, label, method, expected_property, raises=None):
        mock_adapter = MagicMock()
        azure = Azure(adapter=mock_adapter)

        if raises is not None:
            with self.assertRaises(raises):
                assert getattr(azure, method)
        else:
            self.assertEqual(
                first=getattr(getattr(azure, expected_property), method),
                second=getattr(azure, method),
            )

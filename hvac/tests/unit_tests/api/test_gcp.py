from unittest import TestCase

from mock import MagicMock
from parameterized import parameterized, param

from hvac.api.gcp import Gcp
from hvac.api.auth import gcp as gcp_auth_method
from hvac.tests import utils


class TestGcp(utils.HvacIntegrationTestCase, TestCase):

    def test_auth_property(self):
        mock_adapter = MagicMock()
        gcp = Gcp(adapter=mock_adapter)
        self.assertIsInstance(
            obj=gcp.auth,
            cls=gcp_auth_method.Gcp,
        )

    def test_secret_property(self):
        mock_adapter = MagicMock()
        gcp = Gcp(adapter=mock_adapter)
        with self.assertRaises(NotImplementedError):
            assert gcp.secret

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
            raises=AttributeError,
        ),
    ])
    def test_getattr(self, label, method, expected_property, raises=None):
        mock_adapter = MagicMock()
        gcp = Gcp(adapter=mock_adapter)

        if raises is not None:
            with self.assertRaises(raises):
                assert getattr(gcp, method)
        else:
            self.assertEqual(
                first=getattr(getattr(gcp, expected_property), method),
                second=getattr(gcp, method),
            )

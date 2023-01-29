import pytest

from unittest import TestCase

from unittest import mock
from unittest.mock import MagicMock, Mock
from parameterized import parameterized

from hvac.api.secrets_engines.kv import Kv
from hvac.api.secrets_engines.kv_v1 import KvV1
from hvac.api.secrets_engines.kv_v2 import KvV2

from hvac import exceptions


class TestKv(TestCase):
    def test_v1_property(self):
        mock_adapter = MagicMock()
        kv = Kv(adapter=mock_adapter)
        self.assertIsInstance(
            obj=kv.v1,
            cls=KvV1,
        )

    def test_v2_property(self):
        mock_adapter = MagicMock()
        kv = Kv(adapter=mock_adapter)
        self.assertIsInstance(
            obj=kv.v2,
            cls=KvV2,
        )

    @parameterized.expand(
        [
            ("v1", "1"),
            ("v2", "2"),
            ("v3", "3", ValueError),
            ("invalid version", "12345", ValueError),
        ]
    )
    def test_default_kv_version_setter(self, test_label, version, raises=False):
        version_class_map = {
            "1": KvV1,
            "2": KvV2,
        }
        mock_adapter = MagicMock()
        kv = Kv(adapter=mock_adapter)

        if raises:
            with self.assertRaises(raises):
                kv.default_kv_version = version
        else:
            kv.default_kv_version = version
            self.assertIsInstance(
                obj=getattr(kv, "v%s" % version),
                cls=version_class_map.get(version),
            )

    def test_getattr(self):
        mock_adapter = MagicMock()
        kv = Kv(adapter=mock_adapter, default_kv_version="1")
        self.assertEqual(
            first=kv.read_secret,
            second=kv.v1.read_secret,
        )
        kv = Kv(adapter=mock_adapter, default_kv_version="2")
        self.assertEqual(
            first=kv.read_secret_version,
            second=kv.v2.read_secret_version,
        )

        kv._default_kv_version = 0
        with self.assertRaises(AttributeError):
            assert kv.read_secret


class TestKv2:
    # TODO: v3.0.0 - remove this (there should be no more warning, the default will be set statically)
    @pytest.mark.parametrize("raise_on_del", [None, True, False])
    def test_kv2_raise_on_deleted_warning(self, raise_on_del):
        mock_adapter = MagicMock()
        kv = Mock(wraps=Kv(adapter=mock_adapter, default_kv_version="2"))

        for method in [
            kv.read_secret,
            kv.read_secret_version,
            kv.v2.read_secret,
            kv.v2.read_secret_version,
        ]:
            with mock.patch("warnings.warn") as w:
                p = "secret_path"
                method(p, raise_on_deleted_version=raise_on_del)

                if raise_on_del is None:
                    assert w.call_count == 1
                    assert "category" in w.call_args[1]
                    assert w.call_args[1]["category"] == DeprecationWarning
                    # TODO: in py3.8+: assert "category" in w.call_args.kwargs
                    # TODO: in py3.8+: assert w.call_args.kwargs["category"] == DeprecationWarning
                else:
                    assert w.assert_not_called

    @pytest.mark.parametrize(
        ("json", "recoverable"),
        [
            (None, False),
            ({}, False),
            ({"data": {"metadata": {"deletion_time": ""}}}, False),
            ({"data": {"metadata": {"deletion_time": "anything"}}}, True),
        ],
    )
    @pytest.mark.parametrize("raise_on_del", [True, False])
    def test_kv2_raise_on_deleted(self, raise_on_del, json, recoverable):
        def _getem(*args, **kwargs):
            raise exceptions.InvalidPath(json=json)

        mock_adapter = MagicMock(get=_getem)
        kv = Mock(wraps=Kv(adapter=mock_adapter, default_kv_version="2"))

        for method in [
            kv.read_secret,
            kv.read_secret_version,
            kv.v2.read_secret,
            kv.v2.read_secret_version,
        ]:
            p = "secret_path"
            should_raise = raise_on_del or not recoverable

            if should_raise:
                with pytest.raises(exceptions.InvalidPath):
                    method(p, raise_on_deleted_version=raise_on_del)
            else:
                r = method(p, raise_on_deleted_version=raise_on_del)
                assert r is json

import pytest

from pytest_mock import MockFixture
from mock import MagicMock
from unittest import TestCase
import requests_mock
from parameterized import parameterized

from hvac import Client
from hvac.v1 import _sentinel, _smart_pop


class TestSmartPop:
    def test_smart_pop_duplicate(self):
        with pytest.raises(TypeError, match=r"got multiple values for argument"):
            _smart_pop(dict(a=5), "a", posvalue=9)

    def test_smart_pop_missing(self):
        with pytest.raises(
            TypeError, match=r"missing one required positional argument"
        ):
            _smart_pop(dict(a=5), "z")

    @pytest.mark.parametrize("dict", [{}, {"a": 2}])
    @pytest.mark.parametrize("default", [_sentinel, "other"])
    def test_smart_pop_pos_only(self, default, dict, mocker: MockFixture):
        result = _smart_pop(
            dict, "z", default=default, posvalue=mocker.sentinel.pos_only
        )
        assert result is mocker.sentinel.pos_only
        assert "z" not in dict

    @pytest.mark.parametrize("dict", [{}, {"a": 2}])
    def test_smart_pop_default_only(self, dict, mocker: MockFixture):
        result = _smart_pop(dict, "z", default=mocker.sentinel.default_only)
        assert result is mocker.sentinel.default_only
        assert "z" not in dict

    @pytest.mark.parametrize("dict", [{"a": 4, "b": 9}, {"a": 2}])
    def test_smart_pop_warns(self, dict):
        original = dict.copy()
        with pytest.warns(
            DeprecationWarning, match=r"https://github.com/hvac/hvac/issues/1034"
        ):
            result = _smart_pop(dict, "a")
        assert result == original["a"]
        assert "a" not in dict


class TestClientWriteData:
    test_url = "https://vault.example.com"
    test_path = "whatever/fake"
    response = dict(a=1, b="two")

    @pytest.fixture(autouse=True)
    def write_mock(self, requests_mock: requests_mock.Mocker):
        yield requests_mock.register_uri(
            method="POST",
            url=f"{self.test_url}/v1/{self.test_path}",
            json=self.response,
        )

    @pytest.fixture
    def client(self) -> Client:
        return Client(url=self.test_url)

    @pytest.mark.parametrize("wrap_ttl", [None, "3m"])
    def test_write_data(self, client: Client, wrap_ttl: str):
        response = client.write_data(self.test_path, data="cool", wrap_ttl=wrap_ttl)
        assert response == self.response


class TestOldClientWrite:
    test_url = "https://vault.example.com"
    test_path = "whatever/fake"

    @pytest.fixture(autouse=True)
    def mock_write_data(self, mocker: MockFixture) -> MagicMock:
        yield mocker.patch.object(Client, "write_data")

    @pytest.fixture
    def client(self) -> Client:
        return Client(url=self.test_url)

    @pytest.mark.parametrize("kwargs", [{}, {"wrap_ttl": "5m"}, {"other": 5}])
    def test_client_write_no_path(
        self,
        client: Client,
        mocker: MockFixture,
        kwargs: dict,
        mock_write_data: MagicMock,
    ):
        popper = mocker.patch("hvac.v1._smart_pop", new=mocker.Mock(wraps=_smart_pop))
        with pytest.raises(TypeError):
            client.write(**kwargs)
        popper.assert_called_once_with(mocker.ANY, "path", posvalue=_sentinel)
        mock_write_data.assert_not_called()

    @pytest.mark.parametrize("kwargs", [{}, {"other": 5}])
    def test_client_write_no_wrap_ttl(
        self,
        client: Client,
        mocker: MockFixture,
        kwargs: dict,
        mock_write_data: MagicMock,
    ):
        popper = mocker.patch("hvac.v1._smart_pop", new=mocker.Mock(wraps=_smart_pop))
        client.write(self.test_path, **kwargs)
        assert popper.call_count == 2
        expected_call = mocker.call(
            mocker.ANY, "wrap_ttl", default=None, posvalue=_sentinel
        )
        popper.assert_has_calls([expected_call])
        mock_write_data.assert_called_once_with(
            self.test_path, wrap_ttl=None, data=kwargs
        )

    def test_client_write_data_field(
        self, client: Client, mocker: MockFixture, mock_write_data: MagicMock
    ):
        with pytest.warns(
            PendingDeprecationWarning,
            match=r"argument 'data' was supplied as a keyword argument",
        ):
            client.write(self.test_path, data="thing")
        mock_write_data.assert_called_once_with(
            self.test_path, wrap_ttl=None, data=dict(data="thing")
        )


class TestSystemBackendMethods(TestCase):
    """Unit tests providing coverage for Vault system backend-related methods in the hvac Client class."""

    @parameterized.expand(
        [
            ("pki lease ID", "pki/issue/my-role/12c7e036-b59e-5e79-3370-03826fc6f34b"),
        ]
    )
    @requests_mock.Mocker()
    def test_read_lease(self, test_label, test_lease_id, requests_mocker):
        test_path = "http://localhost:8200/v1/sys/leases/lookup"
        mock_response = {
            "issue_time": "2018-07-15T08:35:34.775859245-05:00",
            "renewable": False,
            "id": test_lease_id,
            "ttl": 259199,
            "expire_time": "2018-07-18T08:35:34.00004241-05:00",
            "last_renewal": None,
        }
        requests_mocker.register_uri(
            method="PUT",
            url=test_path,
            json=mock_response,
        )
        client = Client()
        response = client.sys.read_lease(
            lease_id=test_lease_id,
        )
        self.assertEqual(
            first=mock_response,
            second=response,
        )

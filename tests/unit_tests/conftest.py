import pytest

from unittest import mock

from hvac.adapters import Adapter


class MockAdapter(Adapter):
    def __init__(self, *args, **kwargs):
        if "session" not in kwargs:
            kwargs["session"] = mock.MagicMock()
        super().__init__(*args, **kwargs)

    def request(self, *args, **kwargs):
        return (args, kwargs)

    def get_login_token(self, response):
        raise NotImplementedError()


@pytest.fixture
def mock_adapter():
    adapter = MockAdapter()
    with mock.patch.object(adapter, "request", mock.Mock(wraps=MockAdapter.request)):
        yield adapter


@pytest.fixture
def mock_warn():
    with mock.patch("warnings.warn") as warn:
        yield warn

import pytest

from unittest import mock
from hvac.api.auth_methods.token import Token
from hvac.adapters import Adapter


# TODO: move this to a conftest.py somewhere
class MockAdapter(Adapter):
    def __init__(self, *args, **kwargs):
        kwargs["session"] = mock.MagicMock()
        super().__init__(*args, **kwargs)

    def request(self, *args, **kwargs):
        return (args, kwargs)

    def get_login_token(self, response):
        raise NotImplementedError()


@pytest.fixture
def token_auth():
    return Token(MockAdapter())


class TestToken:
    @pytest.mark.parametrize("allowed_policies", ["allowed_policies", None])
    @pytest.mark.parametrize("disallowed_policies", ["disallowed_policies", None])
    @pytest.mark.parametrize("orphan", ["orphan", None])
    @pytest.mark.parametrize("renewable", ["renewable", None])
    @pytest.mark.parametrize("path_suffix", ["path_suffix", None])
    @pytest.mark.parametrize("allowed_entity_aliases", ["allowed_entity_aliases", None])
    @pytest.mark.parametrize("token_period", ["token_period", None])
    @pytest.mark.parametrize("token_explicit_max_ttl", ["token_explicit_max_ttl", None])
    def test_create_or_update_role_optional_parameters(
        self,
        token_auth,
        allowed_policies,
        disallowed_policies,
        orphan,
        renewable,
        path_suffix,
        allowed_entity_aliases,
        token_period,
        token_explicit_max_ttl,
    ):
        params = {
            "allowed_policies": allowed_policies,
            "disallowed_policies": disallowed_policies,
            "orphan": orphan,
            "renewable": renewable,
            "path_suffix": path_suffix,
            "allowed_entity_aliases": allowed_entity_aliases,
            "token_period": token_period,
            "token_explicit_max_ttl": token_explicit_max_ttl,
        }
        expected = params.copy()

        _, rkwargs = token_auth.create_or_update_role("role_name", **params)

        assert "json" in rkwargs
        for key, value in expected.items():
            assert value is None or rkwargs["json"][key] == value

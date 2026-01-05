#!/usr/bin/env python
import pytest
import logging
import time
from unittest import TestCase
from unittest import mock

import requests_mock
from requests_mock.response import create_response
from parameterized import parameterized, param
from hvac.constants.client import DEFAULT_URL
from hvac import exceptions
from hvac import adapters
from hvac.token_cache import TokenCache
from tests import utils
from hvac import Client
import requests


class TestAdapters:
    CONSTRUCTOR_ARGS = (
        "base_uri",
        "token",
        "cert",
        "verify",
        "timeout",
        "proxies",
        "allow_redirects",
        "session",
        "namespace",
        "ignore_exceptions",
        "strict_http",
        "request_header",
    )

    INTERNAL_KWARGS = (
        "cert",
        "verify",
        "timeout",
        "proxies",
    )

    @pytest.mark.parametrize(
        "conargs",
        [
            {arg: arg.capitalize() for arg in CONSTRUCTOR_ARGS},
            {arg: arg.upper() for arg in CONSTRUCTOR_ARGS},
        ],
    )
    def test_from_adapter(self, conargs):
        # set session to None so that the adapter will create its own internally
        conargs["session"] = None
        expected = conargs.copy()
        for internal_kwarg in self.INTERNAL_KWARGS:
            expected.setdefault("_kwargs", {})[internal_kwarg] = expected.pop(
                internal_kwarg
            )

        # let's start with a JSONAdapter, and make a RawAdapter out of it
        json_adapter = adapters.JSONAdapter(**conargs)

        # reset the expected session to to be the one created by the JSONAdapter
        expected["session"] = json_adapter.session

        raw_adapter = adapters.RawAdapter.from_adapter(json_adapter)

        for property, value in expected.items():
            assert getattr(raw_adapter, property) == value


class TestRequest(TestCase):
    """Unit tests providing coverage for requests-related methods in the hvac Client class."""

    @parameterized.expand(
        [
            param(
                "standard Vault address",
                url="https://localhost:8200",
            ),
            param(
                "Vault address with route",
                url="https://example.com/vault",
            ),
            param(
                "regression test for hvac issue #51",
                url="https://localhost:8200",
                path="keyring/http://some.url/sub/entry",
            ),
            param(
                "redirect with location header for issue #343",
                url="https://localhost:8200",
                path="secret/some-secret",
                redirect_url="https://some-other-place.com/secret/some-secret",
            ),
        ]
    )
    def test_get(self, label, url, path="v1/sys/health", redirect_url=None):
        path = path.replace("//", "/")
        expected_status_code = 200
        mock_url = f"{url}/{path}"
        expected_request_urls = [mock_url]
        adapter = adapters.RawAdapter(base_uri=url)
        response_headers = {}
        response_status_code = 200
        if redirect_url is not None:
            response_headers["Location"] = redirect_url
            response_status_code = 301
        with requests_mock.mock() as requests_mocker:
            logging.debug('Registering "mock_url": %s' % mock_url)
            requests_mocker.register_uri(
                method="GET",
                url=mock_url,
                headers=response_headers,
                status_code=response_status_code,
            )
            if redirect_url is not None:
                expected_request_urls.append(redirect_url)
                logging.debug('Registering "redirect_url": %s' % redirect_url)
                requests_mocker.register_uri(
                    method="GET",
                    url=redirect_url,
                )

            response = adapter.get(
                url=path,
            )

        # Assert all our expected uri(s) were requested
        for request_num, expected_request_url in enumerate(expected_request_urls):
            self.assertEqual(
                first=expected_request_url,
                second=requests_mocker.request_history[request_num].url,
            )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            ("kv secret lookup", "v1/secret/some-secret"),
        ]
    )
    @requests_mock.Mocker()
    def test_list(self, test_label, test_path, requests_mocker):
        mock_response = {
            "auth": None,
            "data": {"keys": ["things1", "things2"]},
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "ba933afe-84d4-410f-161b-592a5c016009",
            "warnings": None,
            "wrap_info": None,
        }
        expected_status_code = 200
        mock_url = f"{DEFAULT_URL}/{test_path}"
        requests_mocker.register_uri(method="LIST", url=mock_url, json=mock_response)
        adapter = adapters.RawAdapter()
        response = adapter.list(
            url=test_path,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )
        self.assertEqual(first=mock_response, second=response.json())


@pytest.fixture
def raw_adapter():
    return mock.Mock(wraps=adapters.RawAdapter())


class TestRawAdapter:
    @pytest.mark.parametrize("headers", [{}, {"Content-Type": "application/json"}])
    @pytest.mark.parametrize("json_get", [None, Exception])
    @pytest.mark.parametrize("text_get", [None, Exception])
    @pytest.mark.parametrize(
        "bytes", [None, b"", b"a", b"{}", b'{"errors": ["err"]}', b"\x80\x81", b"\0"]
    )
    @pytest.mark.parametrize("code", [404, 500])
    def test_raise_for_error(
        self, raw_adapter, headers, bytes, code, json_get, text_get
    ):
        url = "throwaway"
        method = "GET"

        resp = create_response(
            mock.Mock(url=url), status_code=code, content=bytes, headers=headers
        )

        resp.json = mock.Mock(wraps=resp.json, side_effect=json_get)

        mock_text = mock.PropertyMock(wraps=resp.text, side_effect=text_get)
        with mock.patch("requests.Response.text", new=mock_text):
            if text_get is not None:
                with pytest.raises(Exception):
                    resp.text

            text = errors = json = None

            if headers:
                try:
                    json = resp.json()
                except Exception:
                    pass
                else:
                    errors = json.get("errors")

            try:
                text = resp.text
            except Exception:
                pass

            from hvac.utils import raise_for_error

            with mock.patch(
                "hvac.utils.raise_for_error", mock.Mock(wraps=raise_for_error)
            ) as r:
                with pytest.raises(exceptions.VaultError) as e:
                    raw_adapter._raise_for_error(method, url, resp)

                e_msg = None if errors else text
                expected = mock.call(
                    method, url, code, e_msg, errors=errors, text=text, json=json
                )

                assert r.call_count == 1
                r.assert_has_calls([expected])
                assert e.value.text == text
                assert e.value.json == json
                assert e.value.errors == errors


class TestAdapterVerify(TestCase):
    @parameterized.expand(
        [
            param("Testing default", verify=Client().session.verify, use_session=False),
            param(
                "Testing default session",
                verify=Client().session.verify,
                use_session=True,
            ),
            param("Testing verify true", verify=True, use_session=False),
            param("Testing verify true session", verify=True, use_session=True),
            param("Testing verify false", verify=False, use_session=False),
            param("Testing verify false session", verify=False, use_session=True),
            param(
                "use certificate for verify #991",
                verify=utils.get_config_file_path("client-cert.pem"),
                use_session=False,
            ),
            param(
                "use certificate from session #991",
                verify=utils.get_config_file_path("client-cert.pem"),
                use_session=True,
            ),
        ]
    )
    def test_session_verify_stickiness(self, label, verify, use_session):
        if use_session:
            s = requests.Session()
            s.verify = verify
            c = Client(session=s)
        elif verify is not None:
            c = Client(verify=verify)
        else:
            c = Client()
        assert c._adapter.session.verify == verify
        assert c._adapter.session

    @parameterized.expand(
        [
            param("Testing default", cert=None, use_session=False),
            param("Testing default with session", cert=None, use_session=False),
            param(
                "use certificate for #991",
                cert=utils.get_config_file_path("client-cert.pem"),
                use_session=False,
            ),
            param(
                "use certificate from session #991",
                cert=utils.get_config_file_path("client-cert.pem"),
                use_session=True,
            ),
        ]
    )
    def test_session_certificate_stickiness(self, label, cert, use_session):
        if use_session:
            s = requests.Session()
            s.cert = cert
            c = Client(session=s)
        elif cert is not None:
            c = Client(cert=cert)
        else:
            c = Client()
        assert c._adapter.session.cert == cert
        assert c._adapter.session

    @parameterized.expand(
        [
            param("Testing default", proxies=None, use_session=False),
            param(
                "Testing default session",
                proxies=None,
                use_session=True,
            ),
            param("Testing Proxy", proxies="localhost:8080", use_session=False),
            param("Testing Proxy session", proxies="localhost:8080", use_session=True),
        ]
    )
    def test_session_proxies_stickiness(self, label, proxies, use_session):
        if use_session:
            s = requests.Session()
            s.proxies = proxies
            c = Client(session=s)
        elif proxies is not None:
            c = Client(proxies=proxies)
        else:
            c = Client()
        assert c._adapter.session.proxies == proxies
        assert c._adapter.session


class TestCachingJSONAdapter:
    """Unit tests for CachingJSONAdapter class."""

    def test_init_default(self):
        """Test CachingJSONAdapter initialization with defaults."""
        adapter = adapters.CachingJSONAdapter()
        assert adapter._token_cache is not None
        assert isinstance(adapter._token_cache, TokenCache)
        assert adapter._current_cache_key is None

    def test_init_with_cache(self):
        """Test CachingJSONAdapter initialization with provided cache."""
        cache = TokenCache()
        adapter = adapters.CachingJSONAdapter(token_cache=cache)
        assert adapter._token_cache is cache

    def test_login_caches_token(self, requests_mock):
        """Test that login auto-generates cache key and caches the token."""
        mock_response = {
            "auth": {
                "client_token": "s.test_token",
                "accessor": "hmac-accessor",
                "policies": ["default", "admin"],
                "lease_duration": 3600,
                "renewable": True,
                "token_type": "service",
            }
        }
        url = f"{DEFAULT_URL}/v1/auth/approle/login"
        requests_mock.register_uri(method="POST", url=url, json=mock_response)

        adapter = adapters.CachingJSONAdapter()
        credentials = {"role_id": "my-role", "secret_id": "my-secret"}
        response = adapter.login(
            url="/v1/auth/approle/login", use_token=True, json=credentials
        )

        # Token should be set on adapter
        assert adapter.token == "s.test_token"

        # Cache key should be auto-generated
        assert adapter._current_cache_key is not None

        # Token should be cached with auto-generated key
        cached_token = adapter._token_cache.get(adapter._current_cache_key)
        assert cached_token == "s.test_token"

        # Metadata should be cached
        metadata = adapter._token_cache.get_metadata(adapter._current_cache_key)
        assert metadata is not None
        assert metadata["ttl"] == 3600
        assert metadata["renewable"] is True
        assert metadata["metadata"]["accessor"] == "hmac-accessor"

    def test_cache_key_generation(self):
        """Test that cache keys are generated deterministically."""
        adapter = adapters.CachingJSONAdapter()

        credentials = {"role_id": "my-role", "secret_id": "my-secret"}
        key1 = adapter._generate_cache_key("/v1/auth/approle/login", json=credentials)
        key2 = adapter._generate_cache_key("/v1/auth/approle/login", json=credentials)

        # Same credentials should generate same key
        assert key1 == key2
        assert len(key1) == 64  # SHA256 hash length

    def test_cache_key_different_credentials(self):
        """Test that different credentials generate different cache keys."""
        adapter = adapters.CachingJSONAdapter()

        creds1 = {"role_id": "role1", "secret_id": "secret1"}
        creds2 = {"role_id": "role2", "secret_id": "secret2"}

        key1 = adapter._generate_cache_key("/v1/auth/approle/login", json=creds1)
        key2 = adapter._generate_cache_key("/v1/auth/approle/login", json=creds2)

        # Different credentials should generate different keys
        assert key1 != key2

    def test_cache_key_different_mount_points(self):
        """Test that different mount points generate different cache keys."""
        adapter = adapters.CachingJSONAdapter()

        credentials = {"role_id": "my-role", "secret_id": "my-secret"}
        key1 = adapter._generate_cache_key("/v1/auth/approle/login", json=credentials)
        key2 = adapter._generate_cache_key("/v1/auth/approle2/login", json=credentials)

        # Different mount points should generate different keys
        assert key1 != key2

    def test_cache_key_different_namespaces(self):
        """Test that different namespaces generate different cache keys."""
        adapter1 = adapters.CachingJSONAdapter(namespace="ns1")
        adapter2 = adapters.CachingJSONAdapter(namespace="ns2")

        credentials = {"role_id": "my-role", "secret_id": "my-secret"}
        key1 = adapter1._generate_cache_key("/v1/auth/approle/login", json=credentials)
        key2 = adapter2._generate_cache_key("/v1/auth/approle/login", json=credentials)

        # Different namespaces should generate different keys
        assert key1 != key2

    def test_invalidate_cached_token(self, requests_mock):
        """Test invalidating a cached token by credentials."""
        mock_response = {
            "auth": {
                "client_token": "s.test_token",
                "lease_duration": 3600,
                "renewable": True,
            }
        }
        url = f"{DEFAULT_URL}/v1/auth/approle/login"
        requests_mock.register_uri(method="POST", url=url, json=mock_response)

        adapter = adapters.CachingJSONAdapter()
        credentials = {"role_id": "my-role", "secret_id": "my-secret"}

        # Login to cache token
        adapter.login(url="/v1/auth/approle/login", use_token=True, json=credentials)
        assert adapter._token_cache.size() == 1

        # Invalidate using same credentials
        adapter.invalidate_cached_token("/v1/auth/approle/login", json=credentials)
        assert adapter._token_cache.size() == 0

    def test_clear_cache(self):
        """Test clearing all cached tokens."""
        cache = TokenCache()
        cache.store(key="key1", token="s.token1", ttl=3600)
        cache.store(key="key2", token="s.token2", ttl=3600)

        adapter = adapters.CachingJSONAdapter(token_cache=cache)
        assert cache.size() == 2

        adapter.clear_cache()
        assert cache.size() == 0

    def test_cached_token_expiration(self, requests_mock):
        """Test that expired cached tokens trigger re-authentication."""
        mock_response = {
            "auth": {
                "client_token": "s.short_lived_token",
                "lease_duration": 1,  # 1 second TTL
                "renewable": False,
            }
        }
        url = f"{DEFAULT_URL}/v1/auth/approle/login"
        requests_mock.register_uri(method="POST", url=url, json=mock_response)

        adapter = adapters.CachingJSONAdapter()
        credentials = {"role_id": "my-role", "secret_id": "my-secret"}

        # First login - caches token
        adapter.login(url="/v1/auth/approle/login", use_token=True, json=credentials)
        assert adapter.token == "s.short_lived_token"
        assert adapter._token_cache.size() == 1

        # Wait for expiration
        time.sleep(1.1)

        # Second login with same credentials - should detect expired cache and re-authenticate
        response = adapter.login(url="/v1/auth/approle/login", use_token=True, json=credentials)

        # Should have made a new request (not returned cached response)
        assert requests_mock.call_count == 2

    def test_shared_cache_across_adapters(self, requests_mock):
        """Test that multiple adapters can share the same cache."""
        shared_cache = TokenCache()

        mock_response = {
            "auth": {
                "client_token": "s.shared_token",
                "lease_duration": 3600,
                "renewable": True,
            }
        }
        url = f"{DEFAULT_URL}/v1/auth/approle/login"
        requests_mock.register_uri(method="POST", url=url, json=mock_response)

        credentials = {"role_id": "my-role", "secret_id": "my-secret"}

        # First adapter logs in and caches token
        adapter1 = adapters.CachingJSONAdapter(token_cache=shared_cache)
        adapter1.login(url="/v1/auth/approle/login", use_token=True, json=credentials)

        # Second adapter with same cache should retrieve cached token
        adapter2 = adapters.CachingJSONAdapter(token_cache=shared_cache)
        response = adapter2.login(url="/v1/auth/approle/login", use_token=True, json=credentials)

        # Should have only made one actual HTTP request
        assert requests_mock.call_count == 1

        # Second adapter should have cached token
        assert adapter2.token == "s.shared_token"

    def test_login_use_token_false(self, requests_mock):
        """Test login with use_token=False still caches token."""
        mock_response = {
            "auth": {
                "client_token": "s.test_token",
                "lease_duration": 3600,
                "renewable": True,
            }
        }
        url = f"{DEFAULT_URL}/v1/auth/approle/login"
        requests_mock.register_uri(method="POST", url=url, json=mock_response)

        adapter = adapters.CachingJSONAdapter()
        credentials = {"role_id": "my-role", "secret_id": "my-secret"}
        response = adapter.login(url="/v1/auth/approle/login", use_token=False, json=credentials)

        # Token should NOT be set on adapter
        assert adapter._base_token is None

        # But token should still be cached for future use
        cache_key = adapter._generate_cache_key("/v1/auth/approle/login", json=credentials)
        assert adapter._token_cache.get(cache_key) == "s.test_token"

#!/usr/bin/env python
import pytest
import logging
from unittest import TestCase
from unittest import mock

import requests_mock
from requests_mock.response import create_response
from parameterized import parameterized, param
from hvac.constants.client import DEFAULT_URL
from hvac import exceptions
from hvac import adapters
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

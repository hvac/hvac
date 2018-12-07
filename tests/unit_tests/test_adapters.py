#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
from unittest import TestCase

import requests_mock
from parameterized import parameterized, param

from hvac import adapters


class TestRequest(TestCase):
    """Unit tests providing coverage for requests-related methods in the hvac Client class."""

    @parameterized.expand([
        param(
            "standard Vault address",
            url='https://localhost:8200',
        ),
        param(
            "Vault address with route",
            url='https://example.com/vault',
        ),
        param(
            "regression test for hvac issue #51",
            url='https://localhost:8200',
            path='keyring/http://some.url/sub/entry',
        ),
        param(
            "redirect with location header for issue #343",
            url='https://localhost:8200',
            path='secret/some-secret',
            redirect_url='https://some-other-place.com/secret/some-secret',

        ),
    ])
    def test_get(self, label, url, path='v1/sys/health', redirect_url=None):
        expected_status_code = 200
        mock_url = '{0}/{1}'.format(url, path)
        adapter = adapters.Request(base_uri=url)
        response_headers = {}
        response_status_code = 200
        if redirect_url is not None:
            response_headers['Location'] = redirect_url
            response_status_code = 301
        with requests_mock.mock() as requests_mocker:
            logging.debug('Registering "mock_url": %s' % mock_url)
            requests_mocker.register_uri(
                method='GET',
                url=mock_url,
                headers=response_headers,
                status_code=response_status_code,
            )
            if redirect_url is not None:
                logging.debug('Registering "redirect_url": %s' % redirect_url)
                requests_mocker.register_uri(
                    method='GET',
                    url=redirect_url,
                )

            response = adapter.get(
                url=path,
            )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

    @parameterized.expand([
        ("kv secret lookup", 'v1/secret/some-secret'),
    ])
    @requests_mock.Mocker()
    def test_list(self, test_label, test_path, requests_mocker):
        mock_response = {
            'auth': None,
            'data': {
                'keys': ['things1', 'things2']
            },
            'lease_duration': 0,
            'lease_id': '',
            'renewable': False,
            'request_id': 'ba933afe-84d4-410f-161b-592a5c016009',
            'warnings': None,
            'wrap_info': None
        }
        expected_status_code = 200
        mock_url = '{0}/{1}'.format(adapters.DEFAULT_BASE_URI, test_path)
        requests_mocker.register_uri(
            method='LIST',
            url=mock_url,
            json=mock_response
        )
        adapter = adapters.Request()
        response = adapter.list(
            url=test_path,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )
        self.assertEqual(
            first=mock_response,
            second=response.json()
        )

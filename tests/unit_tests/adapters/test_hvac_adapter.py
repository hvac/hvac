# (c) 2022, Brian Scholer (@briantist)
# Apache License 2.0 (see LICENSE.txt or https://www.apache.org/licenses/LICENSE-2.0)
# SPDX-License-Identifier: Apache-2.0

import pytest
from unittest import mock

from requests.models import Response

from hvac.adapters import (
    RawAdapter,
    HvacAdapterResponse,
    HvacAdapter,
)


@pytest.fixture
def mock_response():
    return mock.Mock(spec=Response)


@pytest.fixture
def filled_response(mock_response):
    data = {
        "data1": "value1",
        "data2": "value2",
        "auth": {
            "client_token": "opaque",
        }
    }
    mock_response.status_code = 200
    mock_response.json.return_value = data

    return HvacAdapterResponse(mock_response)


class TestHvacAdapter:
    def test_is_raw_adapter(self):
        assert issubclass(HvacAdapter, RawAdapter)

    def test_get_login_token(self, filled_response):
        token = HvacAdapter().get_login_token(filled_response)
        assert token == "opaque"

    @pytest.mark.parametrize(
        "z_args",
        [
            ["arg1"],
            ["arg1", "arg2"],
            [],
        ]
    )
    @pytest.mark.parametrize(
        "z_kwargs",
        [
            {},
            {"kw1": "val1"},
            {"kw1": "val1", "kw2": 2},
        ]
    )
    def test_request(self, z_args, z_kwargs, filled_response):
        with mock.patch.object(RawAdapter, 'request', mock.Mock(return_value=filled_response)) as req:
            adapter = HvacAdapter()
            result = adapter.request(*z_args, **z_kwargs)

            req.assert_called_once_with(*z_args, **z_kwargs)
            assert isinstance(result, HvacAdapterResponse)
            assert result.raw is filled_response

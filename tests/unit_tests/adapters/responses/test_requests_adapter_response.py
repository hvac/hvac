# (c) 2022, Brian Scholer (@briantist)
# Apache License 2.0 (see LICENSE.txt or https://www.apache.org/licenses/LICENSE-2.0)
# SPDX-License-Identifier: Apache-2.0

import pytest
from unittest import mock

from hvac.adapters import AdapterResponse, RequestsAdapterResponse
from requests.models import Response


@pytest.fixture(autouse=True)
def concretify():
    with mock.patch.object(RequestsAdapterResponse, '__abstractmethods__', set()) as o:
        yield o


@pytest.fixture
def mock_response():
    return mock.Mock(spec=Response)


class TestRequestsAdapterResponse:
    def test_is_adapter_response(self):
        assert issubclass(RequestsAdapterResponse, AdapterResponse)

    def test_thing(self, mock_response):
        mock_response.status_code = 200
        mock_response.json.return_value = dict(data=dict(hello="hi"))

        rar = RequestsAdapterResponse(mock_response)

        assert rar.raw is mock_response
        assert rar.status == mock_response.status_code == 200

        with pytest.raises(NotImplementedError):
            rar.value

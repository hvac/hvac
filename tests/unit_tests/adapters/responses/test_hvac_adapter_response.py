# (c) 2022, Brian Scholer (@briantist)
# Apache License 2.0 (see LICENSE.txt or https://www.apache.org/licenses/LICENSE-2.0)
# SPDX-License-Identifier: Apache-2.0

import pytest
from unittest import mock

from hvac.adapters import HvacAdapterResponse, RequestsAdapterResponse
from requests.models import Response


@pytest.fixture
def mock_response():
    return mock.Mock(spec=Response)


class TestHvacAdapterResponse:
    def test_is_adapter_response(self):
        assert issubclass(HvacAdapterResponse, RequestsAdapterResponse)

    def test_http_200(self, mock_response):
        data = dict(data=dict(hello="hi"))
        mock_response.status_code = 200
        mock_response.json.return_value = data

        rar = HvacAdapterResponse(mock_response)

        assert rar.raw is mock_response
        assert rar.status == mock_response.status_code == 200

        with pytest.raises(AttributeError):
            rar._value

        mock_response.json.assert_not_called()

        assert rar.value == data
        assert rar._value == data

        mock_response.json.assert_called_once()

    def test_http_204(self, mock_response):
        mock_response.status_code = 204
        mock_response.json.side_effect = ValueError

        rar = HvacAdapterResponse(mock_response)

        assert rar.raw is mock_response
        assert rar.status == mock_response.status_code == 204

        with pytest.raises(AttributeError):
            rar._value

        mock_response.json.assert_not_called()

        assert rar.value == {}
        assert rar._value == {}

        mock_response.json.assert_called_once()

    def test_unparseable(self, mock_response):
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError

        rar = HvacAdapterResponse(mock_response)

        assert rar.raw is mock_response
        assert rar.status == mock_response.status_code == 200

        with pytest.raises(AttributeError):
            rar._value

        mock_response.json.assert_not_called()

        assert rar.value is None
        assert rar._value is None

        mock_response.json.assert_called_once()

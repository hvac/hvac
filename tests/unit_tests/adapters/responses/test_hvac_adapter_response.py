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


@pytest.fixture
def filled_response(mock_response):
    data = {
        "data1": "value1",
        "data2": "value2",
    }
    mock_response.status_code = 200
    mock_response.json.return_value = data

    return HvacAdapterResponse(mock_response)


@pytest.fixture
def mock_warn():
    with mock.patch("warnings.warn") as w:
        yield w


class TestHvacAdapterResponse:
    def test_is_adapter_response(self):
        assert issubclass(HvacAdapterResponse, RequestsAdapterResponse)

    @pytest.mark.parametrize("status", [200, 204, 301])
    def test_parseable(self, mock_response, status):
        data = dict(data=dict(hello="hi"))
        mock_response.status_code = status
        mock_response.json.return_value = data

        rar = HvacAdapterResponse(mock_response)

        assert rar.raw is mock_response
        assert rar.status == mock_response.status_code == status

        with pytest.raises(AttributeError):
            rar._value

        mock_response.json.assert_not_called()

        assert rar.value == data
        assert rar._value == data

        mock_response.json.assert_called_once()

    def test_http_204_empty(self, mock_response):
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

    def test_non_204_unparseable(self, mock_response):
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

    # test deprecated fallback stuff

    def test_general_attr_access(self, mock_response, filled_response, mock_warn):
        v = filled_response.get("data1")

        mock_warn.assert_called_once()
        assert v == mock_response.json()["data1"]
        assert v == filled_response.value["data1"]

    def test_getitem(self, mock_response, filled_response, mock_warn):
        v = filled_response["data1"]

        mock_warn.assert_called_once()
        assert v == mock_response.json()["data1"]
        assert v == filled_response.value["data1"]

    def test_setitem(self, mock_response, filled_response, mock_warn):
        v = "a1"
        filled_response["new1"] = v

        mock_warn.assert_called_once()
        assert len(filled_response.value) == 3
        assert v == filled_response.value["new1"]
        assert v == mock_response.json()["new1"]

    def test_delitem(self, mock_response, filled_response, mock_warn):
        del filled_response["data2"]

        mock_warn.assert_called_once()
        assert len(filled_response.value) == 1
        assert "data2" not in filled_response.value
        assert "value1" == filled_response.value["data1"]
        assert "value1" == mock_response.json()["data1"]

    def test_len(self, filled_response, mock_warn):
        assert len(filled_response) == len(filled_response.value)
        mock_warn.assert_called_once()

    def test_in(self, filled_response, mock_warn):
        assert "data2" in filled_response
        mock_warn.assert_called_once()

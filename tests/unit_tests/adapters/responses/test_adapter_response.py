# (c) 2022, Brian Scholer (@briantist)
# Apache License 2.0 (see LICENSE.txt or https://www.apache.org/licenses/LICENSE-2.0)
# SPDX-License-Identifier: Apache-2.0

import pytest
from unittest import mock

from hvac.adapters import AdapterResponse


ABSTRACT_METHODS = set(
    [
        "raw",
        "status",
        "value",
    ]
)


class TestAbstractAdapterResponse:
    @pytest.mark.parametrize("method", ABSTRACT_METHODS)
    def test_has_abstract_methods(self, method):
        assert method in AdapterResponse.__abstractmethods__, repr(
            AdapterResponse.__abstractmethods__
        )

    def test_has_only_expected_abstract_methods(self):
        for abstract_method in AdapterResponse.__abstractmethods__:
            assert abstract_method in ABSTRACT_METHODS

    @mock.patch.object(AdapterResponse, "__abstractmethods__", set())
    @pytest.mark.parametrize("method", ABSTRACT_METHODS)
    def test_not_implemented(self, method):
        with pytest.raises(NotImplementedError):
            getattr(AdapterResponse(), method)()

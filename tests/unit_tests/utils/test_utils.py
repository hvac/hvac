import pytest
import warnings

from unittest import mock

from hvac.utils import (
    generate_method_deprecation_message,
    generate_property_deprecation_message,
    generate_parameter_deprecation_message,
    aliased_parameter,
    comma_delimited_to_list,
    get_token_from_env,
)


@pytest.fixture
def aliasable_func():
    def _func(pos0, pos1=None, *, kw0, kw1="kwone", kw2=None):
        return {
            "pos0": pos0,
            "pos1": pos1,
            "kw0": kw0,
            "kw1": kw1,
            "kw2": kw2,
        }

    return _func


class TestUtils:
    @pytest.mark.parametrize("token", ["token", "token2 ", " ", "\n"])
    def test_get_token_from_env_env_var(self, token):
        with mock.patch.dict("os.environ", {"VAULT_TOKEN": token}):
            with mock.patch("builtins.open", mock.mock_open()) as mopen:
                result = get_token_from_env()

                mopen.assert_not_called()
                assert result == token

    @mock.patch.dict("os.environ", clear=True)
    @mock.patch("os.path.expanduser", mock.Mock(return_value="/a/b/c/token"))
    @pytest.mark.parametrize("token", ["token", "token2 ", "", " ", "\n"])
    @pytest.mark.parametrize("exists", [True, False])
    def test_get_token_from_env_token_sink(self, token, exists):
        with mock.patch("os.path.exists", lambda x: exists):
            with mock.patch("builtins.open", mock.mock_open(read_data=token)) as mopen:
                result = get_token_from_env()

                if exists:
                    mopen.assert_called_once_with("/a/b/c/token")
                    if token.strip():
                        assert result == token.strip()
                    else:
                        assert result is None
                else:
                    mopen.assert_not_called()
                    assert result is None

    @pytest.mark.parametrize(
        "list_param",
        [[], ["one"], [1, "two"], [1, "2", None], ["1", None, ["!", "@"], {}]],
    )
    def test_comma_delimited_to_list_from_list(self, list_param):
        result = comma_delimited_to_list(list_param=list_param)
        assert result == list_param

    @pytest.mark.parametrize(
        "list_param",
        [{}, {"a": 1}, None, 7, b"X,Y,Z"],
    )
    def test_comma_delimited_to_list_from_other(self, list_param):
        result = comma_delimited_to_list(list_param=list_param)
        assert result == []

    @pytest.mark.parametrize(
        ("list_param", "expected"),
        [
            ("", [""]),
            ("a", ["a"]),
            ("a,b,c", ["a", "b", "c"]),
            ("a, b, c", ["a", " b", " c"]),
            ("a,,c", ["a", "", "c"]),
        ],
    )
    def test_comma_delimited_to_list_from_str(self, list_param, expected):
        result = comma_delimited_to_list(list_param=list_param)
        assert result == expected

    @pytest.mark.parametrize("to_be_removed_in_version", ["99.0.0"])
    @pytest.mark.parametrize("old_name", ["old_one"])
    @pytest.mark.parametrize("new_name", ["new_one"])
    @pytest.mark.parametrize("new_attribute", ["new_attr"])
    @pytest.mark.parametrize("module_name", ["Client", "modulename"])
    def test_generate_property_deprecation_message(
        self,
        to_be_removed_in_version,
        old_name,
        new_name,
        new_attribute,
        module_name,
    ):
        result = generate_property_deprecation_message(
            to_be_removed_in_version=to_be_removed_in_version,
            old_name=old_name,
            new_name=new_name,
            new_attribute=new_attribute,
            module_name=module_name,
        )

        assert to_be_removed_in_version in result
        assert old_name in result
        assert new_name in result
        assert module_name in result

    @pytest.mark.parametrize("to_be_removed_in_version", ["99.0.0"])
    @pytest.mark.parametrize("old_method_name", ["old_one"])
    @pytest.mark.parametrize("method_name", [None, "new_one"])
    @pytest.mark.parametrize("module_name", [None, "modulename"])
    def test_generate_method_deprecation_message(
        self,
        to_be_removed_in_version,
        old_method_name,
        method_name,
        module_name,
    ):
        result = generate_method_deprecation_message(
            to_be_removed_in_version=to_be_removed_in_version,
            old_method_name=old_method_name,
            method_name=method_name,
            module_name=module_name,
        )

        assert to_be_removed_in_version in result
        assert old_method_name in result
        if method_name is not None and module_name is not None:
            assert method_name in result and module_name in result

    @pytest.mark.parametrize("to_be_removed_in_version", ["99.0.0"])
    @pytest.mark.parametrize("old_parameter_name", ["old_one"])
    @pytest.mark.parametrize("new_parameter_name", [None, "new_one"])
    @pytest.mark.parametrize("extra_notes", [None, "See also whatever."])
    def test_generate_parameter_deprecation_message(
        self,
        to_be_removed_in_version,
        old_parameter_name,
        new_parameter_name,
        extra_notes,
    ):
        result = generate_parameter_deprecation_message(
            to_be_removed_in_version=to_be_removed_in_version,
            old_parameter_name=old_parameter_name,
            new_parameter_name=new_parameter_name,
            extra_notes=extra_notes,
        )

        assert to_be_removed_in_version in result
        assert old_parameter_name in result
        assert (new_parameter_name is None) or (new_parameter_name in result)
        assert (extra_notes is None) or (extra_notes in result)

    @pytest.mark.parametrize("removed_in_version", ["abc", "123", None])
    @pytest.mark.parametrize(
        ["raise_on_multiple", "position", "i_args", "i_kwargs", "raises", "p1exp"],
        [
            (True, 1, ["p0"], {"kw0": "kw0", "alias8": "eight"}, None, "eight"),
            (True, None, ["p0"], {"kw0": "kw0", "alias8": "eight"}, None, "eight"),
            (
                True,
                1,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "pos1": "p1"},
                ValueError,
                None,
            ),
            (
                True,
                None,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "pos1": "p1"},
                ValueError,
                None,
            ),
            (
                True,
                1,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine", "pos1": "p1"},
                ValueError,
                None,
            ),
            (
                True,
                None,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine", "pos1": "p1"},
                ValueError,
                None,
            ),
            (
                True,
                1,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine"},
                ValueError,
                None,
            ),
            (
                True,
                None,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine"},
                ValueError,
                None,
            ),
            (
                True,
                1,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "pos1": "peeone"},
                ValueError,
                None,
            ),
            (
                True,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "pos1": "p1"},
                ValueError,
                None,
            ),
            (
                True,
                1,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight"},
                ValueError,
                None,
            ),
            (
                True,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight"},
                TypeError,
                None,
            ),
            (
                True,
                1,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine", "pos1": "p1"},
                ValueError,
                None,
            ),
            (
                True,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine", "pos1": "peeone"},
                ValueError,
                None,
            ),
            (
                True,
                1,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine"},
                ValueError,
                None,
            ),
            (
                True,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine"},
                ValueError,
                None,
            ),
            (True, 1, ["p0", "p1"], {"kw0": "kw0", "pos1": "peeone"}, TypeError, None),
            (
                True,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "pos1": "peeone"},
                TypeError,
                None,
            ),
            (True, 1, ["p0", "p1"], {"kw0": "kw0"}, None, "p1"),
            (True, None, ["p0", "p1"], {"kw0": "kw0"}, None, "p1"),
            (False, 1, ["p0"], {"kw0": "kw0", "alias8": "eight"}, None, "eight"),
            (False, None, ["p0"], {"kw0": "kw0", "alias8": "eight"}, None, "eight"),
            (
                False,
                1,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "pos1": "p1"},
                None,
                "p1",
            ),
            (
                False,
                None,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "pos1": "p1"},
                None,
                "p1",
            ),
            (
                False,
                1,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine", "pos1": "p1"},
                None,
                "p1",
            ),
            (
                False,
                None,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine", "pos1": "p1"},
                None,
                "p1",
            ),
            (
                False,
                1,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine"},
                None,
                "nine",
            ),
            (
                False,
                None,
                ["p0"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine"},
                None,
                "nine",
            ),
            (
                False,
                1,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "pos1": "peeone"},
                TypeError,
                None,
            ),
            (
                False,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "pos1": "peeone"},
                TypeError,
                None,
            ),
            (False, 1, ["p0", "p1"], {"kw0": "kw0", "alias8": "eight"}, None, "p1"),
            (
                False,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight"},
                TypeError,
                None,
            ),
            (
                False,
                1,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine", "pos1": "peeone"},
                TypeError,
                None,
            ),
            (
                False,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine", "pos1": "peeone"},
                TypeError,
                None,
            ),
            (
                False,
                1,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine"},
                None,
                "p1",
            ),
            (
                False,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "alias8": "eight", "alias9": "nine"},
                TypeError,
                None,
            ),
            (False, 1, ["p0", "p1"], {"kw0": "kw0", "pos1": "peeone"}, TypeError, None),
            (
                False,
                None,
                ["p0", "p1"],
                {"kw0": "kw0", "pos1": "peeone"},
                TypeError,
                None,
            ),
            (False, 1, ["p0", "p1"], {"kw0": "kw0"}, None, "p1"),
            (False, None, ["p0", "p1"], {"kw0": "kw0"}, None, "p1"),
        ],
    )
    def test_aliased_parameter(
        self,
        aliasable_func,
        removed_in_version,
        raise_on_multiple,
        i_args,
        i_kwargs,
        raises,
        p1exp,
        position,
    ):
        wrapped = aliased_parameter(
            "pos1",
            "alias9",
            "alias8",
            removed_in_version=removed_in_version,
            position=position,
            raise_on_multiple=raise_on_multiple,
        )(aliasable_func)

        alias_count = 0
        for a in i_kwargs.keys():
            if "alias" in a:
                alias_count += 1

        if raises is not None:
            with pytest.raises(raises, match=r"pos1"):
                if removed_in_version is None or alias_count == 0:
                    with warnings.catch_warnings():
                        warnings.simplefilter("error")
                        result = wrapped(*i_args, **i_kwargs)
                else:
                    with pytest.warns(DeprecationWarning) as wrecs:
                        result = wrapped(*i_args, **i_kwargs)
                        assert len(wrecs) == alias_count
                        for w in wrecs:
                            assert removed_in_version in str(w)
        else:
            if removed_in_version is None or alias_count == 0:
                with warnings.catch_warnings():
                    warnings.simplefilter("error")
                    result = wrapped(*i_args, **i_kwargs)
            else:
                with pytest.warns(DeprecationWarning) as wrecs:
                    result = wrapped(*i_args, **i_kwargs)
                    assert len(wrecs) == alias_count
                    for w in wrecs:
                        assert removed_in_version in str(w)

            assert result["pos0"] == "p0"
            assert result["pos1"] == p1exp
            assert result["kw0"] == "kw0"
            assert result["kw2"] is None
            assert "alias8" not in result
            assert "alias9" not in result

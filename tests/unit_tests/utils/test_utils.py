import pytest

from hvac.utils import generate_parameter_deprecation_message


class TestUtils:
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

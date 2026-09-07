import pytest

from hvac import exceptions


class TestVaultError:
    @pytest.mark.parametrize(
        "status_code,expected_class",
        [
            (400, exceptions.InvalidRequest),
            (404, exceptions.InvalidPath),
            (503, exceptions.VaultDown),
            (423, exceptions.UnexpectedError),
            (504, exceptions.UnexpectedError),
        ],
    )
    def test_from_status_keeps_the_status_code(self, status_code, expected_class):
        error = exceptions.VaultError.from_status(
            status_code, "boom", method="POST", url="https://vault.example/v1/x"
        )

        assert isinstance(error, expected_class)
        assert error.status_code == status_code
        assert str(error) == "boom, on POST https://vault.example/v1/x"

    def test_status_code_defaults_to_none(self):
        assert exceptions.VaultError("boom").status_code is None
        assert exceptions.UnexpectedError("boom", status_code=418).status_code == 418

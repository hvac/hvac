from hvac.api.auth_methods import JWT

import requests_mock
from parameterized import parameterized

from hvac.adapters import JSONAdapter

import json


class ValueChecker:
    def __init__(self, expected_body_params, return_status_code):
        self.expected_body_params = expected_body_params
        self.return_status_code = return_status_code
        self.expected_headers = {
            "X-Vault-Request": "true",
            "Content-Type": "application/json",
        }

    def text_callback(self, request, context):
        rq_params = json.loads(request.body)
        assert rq_params == self.expected_body_params
        rq_headers = {
            k: v for k, v in request.headers.items() if k in self.expected_headers
        }
        assert rq_headers == self.expected_headers
        context.status_code = self.return_status_code


@parameterized.expand(
    [
        (
            "hvac",
            "https://vault/user",
            ["https://localhost:8200/jwt-test/callback"],
            "jwt",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "string",
            False,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "hvac",
            "https://vault/user",
            ["https://localhost:8200/jwt-test/callback"],
            "jwt",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "string",
            False,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            False,
        ),
        (
            "hvac",
            "https://vault/user",
            ["https://localhost:8200/jwt-test/callback"],
            "jwt",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "string",
            False,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            True,
        ),
    ]
)
@requests_mock.Mocker()
def test_create_role(
    name,
    user_claim,
    allowed_redirect_uris,
    role_type,  # = "jwt"
    bound_audiences,
    clock_skew_leeway,
    expiration_leeway,
    not_before_leeway,
    bound_subject,
    bound_claims,
    groups_claim,
    claim_mappings,
    oidc_scopes,
    bound_claims_type,  # ="string"
    verbose_oidc_logging,  # =False,
    token_ttl,
    token_max_ttl,
    token_policies,
    token_bound_cidrs,
    token_explicit_max_ttl,
    token_no_default_policy,
    token_num_uses,
    token_period,
    token_type,
    path,
    user_claim_json_pointer,
    requests_mocker,
):

    test_arguments = {
        "name": name,
        "role_type": role_type,
        "bound_audiences": bound_audiences,
        "user_claim": user_claim,
        "clock_skew_leeway": clock_skew_leeway,
        "expiration_leeway": expiration_leeway,
        "not_before_leeway": not_before_leeway,
        "bound_subject": bound_subject,
        "bound_claims": bound_claims,
        "groups_claim": groups_claim,
        "claim_mappings": claim_mappings,
        "oidc_scopes": oidc_scopes,
        "allowed_redirect_uris": allowed_redirect_uris,
        "bound_claims_type": bound_claims_type,
        "verbose_oidc_logging": verbose_oidc_logging,
        "token_ttl": token_ttl,
        "token_max_ttl": token_max_ttl,
        "token_policies": token_policies,
        "token_bound_cidrs": token_bound_cidrs,
        "token_explicit_max_ttl": token_explicit_max_ttl,
        "token_no_default_policy": token_no_default_policy,
        "token_num_uses": token_num_uses,
        "token_period": token_period,
        "token_type": token_type,
        "user_claim_json_pointer": user_claim_json_pointer,
    }

    check_arguments = {k: v for k, v in test_arguments.items() if v is not None}
    expected_status_code = 204

    eff_path = "jwt" if path is None else path
    mock_url = f"http://localhost:8200/v1/auth/{eff_path}/role/{name}"
    requests_mocker.register_uri(
        method="POST",
        url=mock_url,
        text=ValueChecker(check_arguments, expected_status_code).text_callback,
    )
    jwt = JWT(adapter=JSONAdapter())
    actual_response = jwt.create_role(**test_arguments)
    assert expected_status_code == actual_response.status_code

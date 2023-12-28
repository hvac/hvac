#!/usr/bin/env python
"""Support for "MFA"-related System Backend Methods."""
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class MFA(SystemBackendMixin):

    def validate_mfa(self, mfa_request_id, mfa_payload, use_token=True):
        """Validate a login request which is subject to MFA validation.

        Supported methods:
            GET: /sys/mfa/validate. Produces: 200 application/json

        :param mfa_request_id: Unique identification of an MFA restricted login request.
            This comes from the MFA requirement in the auth response of the login request.
        :type mfa_request_id: str | unicode
        :param mfa_payload: Map of MFA method IDs to passcode credentials.
            MFA method IDs are UUID strings which are used as keys of the dict.
            For vault 1.13.0 and above, the keys can be MFA method names instead of IDs.
            The values of the dict are lists of passcodes as strings. If the MFA method
            is configured not to use passcodes, the passcode remains an empty string.
        :type mfa_payload: dict[str, list[str]]
        :param use_token: if True, uses the token in the response received from the MFA request to set the "token"
            attribute on the :py:meth:`hvac.adapters.Adapter` instance under the _adapter Client attribute.
        :type use_token: bool
        :return: The response of the MFA validation request.
        :rtype: dict
        """
        api_path = "/v1/sys/mfa/validate"
        params = {"mfa_request_id": mfa_request_id, "mfa_payload": mfa_payload}
        # reuse the login method to set the token in the adapter if requested.
        return self._adapter.login(
            url=api_path,
            use_token=use_token,
            json=params,
        )

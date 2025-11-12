from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class Wrapping(SystemBackendMixin):
    def unwrap(self, token=None, use_token_to_authenticate=False):
        """Return the original response inside the given wrapping token.

        Unlike simply reading cubbyhole/response (which is deprecated), this endpoint provides additional validation
        checks on the token, returns the original value on the wire rather than a JSON string representation of it, and
        ensures that the response is properly audit-logged.

        Supported methods:
            POST: /sys/wrapping/unwrap. Produces: 200 application/json

        :param token: Specifies the wrapping token ID. This is required if the client token is not the wrapping token.
            Do not use the wrapping token in both locations.
        :type token: str | unicode
        :param use_token_to_authenticate: If True will set the "X-Vault-Token" request param to token and not put it in the payload.
        :type use_token_to_authenticate: bool
        :return: The JSON response of the request.
        :rtype: dict
        """
        params = {}
        headers = {}
        if token is not None:
            if not use_token_to_authenticate:
                params["token"] = token
            else:
                headers["X-Vault-Token"] = token

        api_path = "/v1/sys/wrapping/unwrap"
        return self._adapter.post(url=api_path, json=params, headers=headers)

    def wrap(self, payload=None, ttl=60):
        """Wraps a serializable dictionary inside a wrapping token.

        Supported methods:
            POST: /sys/wrapping/wrap. Produces: 200 application/json

        :param payload: Specifies the data that should be wrapped inside the token.
        :type payload: dict
        :param ttl: The TTL of the returned wrapping token.
        :type ttl: int
        :return: The JSON response of the request.
        :rtype: dict
        """

        if payload is None:
            payload = {}

        api_path = "/v1/sys/wrapping/wrap"
        return self._adapter.post(
            url=api_path, json=payload, headers={"X-Vault-Wrap-TTL": "{}".format(ttl)}
        )

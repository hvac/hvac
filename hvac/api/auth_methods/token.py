#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Token module."""
from hvac.api.vault_api_base import VaultApiBase
from hvac.adapters import Request


class Token(VaultApiBase):
    """Token class to support token auth ONLY"""

    class TokenAdapter(Request):
        """Basic request adapter except the login doesn't really do anything"""
        def login(self, url, use_token=False, **kwargs):
            """Perform a login request.

                    Associated request is typically to a path prefixed with "/v1/auth") and optionally stores the client token sent
                        in the resulting Vault response for use by the :py:meth:`hvac.adapters.Adapter` instance under the _adapater
                        Client attribute.

                    :param url: Path to send the authentication request to.
                    :type url: str | unicode
                    :param use_token: if True, uses the token in the response received from the auth request to set the "token"
                        attribute on the the :py:meth:`hvac.adapters.Adapter` instance under the _adapater Client attribute.
                    :type use_token: bool
                    :param kwargs: Additional keyword arguments to include in the params sent with the request.
                    :type kwargs: dict
                    :return: The response of the auth request.
                    :rtype: requests.Response
                    """
            response = self.post(url, **kwargs).json()

            if use_token:
                self.token = response['auth']['client_token']

            return response

    def __init__(self, adapter=TokenAdapter):
        """Default token class constructor.

                :param adapter: Instance of :py:class:`hvac.adapters.Adapter`; used for performing HTTP requests.
                :type adapter: hvac.adapters.Adapter
                """
        self._adapter = adapter

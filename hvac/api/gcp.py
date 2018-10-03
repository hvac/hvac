"""Gcp auth method and secret engine wrapper module."""

import logging

from hvac.api.auth import gcp as gcp_auth_method
# from hvac.api.secrets_engines import gcp as gcp_secret_engine
from hvac.api.vault_api_base import VaultApiBase

logger = logging.getLogger(__name__)


class Gcp(VaultApiBase):
    """Class containing methods for the gcp auth method and secrets engines backend API routes.
    Reference: https://www.vaultproject.io/api/secret/gcp/index.html
    https://www.vaultproject.io/api/auth/gcp/index.html

    """

    def __init__(self, adapter):
        """Create a new Gcp instance.

        :param adapter: Instance of :py:class:`hvac.adapters.Adapter`; used for performing HTTP requests.
        :type adapter: hvac.adapters.Adapter
        """
        super(Gcp, self).__init__(adapter=adapter)

        self._gcp_auth = gcp_auth_method.Gcp(adapter=self._adapter)
        # self._gcp_secret = gcp_secret_engine.Gcp(adapter=self._adapter)

    @property
    def auth(self):
        """Accessor for Gcp auth method instance. Provided via the :py:class:`hvac.api.auth.Gcp` class.

        :return: This Gcp instance's associated auth.Gcp instance.
        :rtype: hvac.api.auth.Gcp
        """
        return self._gcp_auth

    @property
    def secret(self):
        """Accessor for Gcp secret engine instance. Provided via the :py:class:`hvac.api.secrets_engines.Gcp` class.

        .. warning::

            Support for the GCP secret engine is not currently implemented.

        :return: This Gcp instance's associated secrets_engines.Gcp instance.
        :rtype: hvac.api.secrets_engines.Gcp
        """
        raise NotImplementedError

    def __getattr__(self, item):
        """Overridden magic method used to direct method calls to the appropriate auth or secret Gcp instance.

        :param item: Name of the attribute/method being accessed
        :type item: str | unicode
        :return: The related auth method or secret engine class for the requested method.
        :rtype: hvac.api.vault_api_base.VaultApiBase
        """
        if hasattr(self._gcp_auth, item):
            return getattr(self._gcp_auth, item)
        # elif hasattr(self._gcp_secret, item):
        #     return getattr(self._gcp_secret, item)

        raise AttributeError

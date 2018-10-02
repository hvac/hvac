"""Azure auth method and secret engine wrapper module."""

import logging

from hvac.api.auth import azure as azure_auth_method
# from hvac.api.secrets_engines import azure as azure_secret_engine
from hvac.api.vault_api_base import VaultApiBase

logger = logging.getLogger(__name__)


class Azure(VaultApiBase):
    """Class containing methods for the azure auth method and secrets engines backend API routes.
    Reference: https://www.vaultproject.io/api/secret/azure/index.html
    https://www.vaultproject.io/api/auth/azure/index.html

    """

    def __init__(self, adapter):
        """Create a new Azure instance.

        :param adapter: Instance of :py:class:`hvac.adapters.Adapter`; used for performing HTTP requests.
        :type adapter: hvac.adapters.Adapter
        """
        super(Azure, self).__init__(adapter=adapter)

        self._azure_auth = azure_auth_method.Azure(adapter=self._adapter)
        # self._azure_secret = azure_secret_engine.Azure(adapter=self._adapter)

    @property
    def auth(self):
        """Accessor for Azure auth method instance. Provided via the :py:class:`hvac.api.auth.Azure` class.

        :return: This Azure instance's associated auth.Azure instance.
        :rtype: hvac.api.auth.Azure
        """
        return self._azure_auth

    @property
    def secret(self):
        """Accessor for Azure secret engine instance. Provided via the :py:class:`hvac.api.secrets_engines.Azure` class.
        .. warning::

            Note: Not currently implemented.

        :return: This Azure instance's associated secrets_engines.Azure instance.
        :rtype: hvac.api.secrets_engines.Azure
        """
        raise NotImplementedError

    def __getattr__(self, item):
        """Overridden magic method used to direct method calls to the appropriate auth or secret Azure instance.

        :param item: Name of the attribute/method being accessed
        :type item: str | unicode
        :return: The related auth method or secret engine class for the requested method.
        :rtype: hvac.api.vault_api_base.VaultApiBase
        """
        if hasattr(self._azure_auth, item):
            return getattr(self._azure_auth, item)
        # elif hasattr(self._azure_secret, item):
        #     return getattr(self._azure_secret, item)

        raise AttributeError

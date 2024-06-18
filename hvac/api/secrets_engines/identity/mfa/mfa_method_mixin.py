from abc import ABCMeta, abstractmethod

from hvac import utils
from hvac.api.vault_api_base import VaultApiBase
from hvac.constants.identity import DEFAULT_MOUNT_POINT


class MfaMethodMixin(VaultApiBase, metaclass=ABCMeta):
    """Base class for Identity MFA Method Type API endpoints."""

    @property
    @abstractmethod
    def method_type(self):
        """Name of the Identity MFA Method Type

        :return: name of the Identity MFA Method Type
        :rtype: str | unicode
        """
        raise NotImplementedError

    @abstractmethod
    def create(self, *args, **kwargs):
        """Create an MFA method of this type."""
        raise NotImplementedError

    @abstractmethod
    def update(self, *args, **kwargs):
        """Create an MFA method of this type."""
        raise NotImplementedError

    def read(self, method_id, mount_point=DEFAULT_MOUNT_POINT):
        """
        Read an MFA method of this class's method_type (duo, okta, pingid, totp).

        Supported methods:
            GET: /{mount_point}/mfa/method/{method_type}/{method_id}. Produces: 200 application/json

        :param method_id: The UUID of the MFA method.
        :type method_id: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_mfa_methods request.
        :rtype: dict
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/method/{method_type}/{method_id}",
            mount_point=mount_point,
            method_type=self.method_type,
            method_id=method_id,
        )
        return self._adapter.get(url=api_path)

    def delete(self, method_id, mount_point=DEFAULT_MOUNT_POINT):
        """
        Delete an MFA method of this class's method_type (duo, okta, pingid, totp).

        Supported methods:
            DELETE: /{mount_point}/mfa/method/{method_type}/{method_id}. Produces: 204 (empty body)

        :param method_id: The UUID of the MFA method.
        :type method_id: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_mfa_methods request.
        :rtype: dict
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/method/{method_type}/{method_id}",
            mount_point=mount_point,
            method_type=self.method_type,
            method_id=method_id,
        )
        return self._adapter.delete(url=api_path)

    def list(self, mount_point=DEFAULT_MOUNT_POINT):
        """
        List MFA methods of this class's method_type (duo, okta, pingid, totp).

        Supported methods:
            LIST: /{mount_point}/mfa/method/{method_type}. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_mfa_methods request.
        :rtype: dict
        """
        api_path = utils.format_url(
            "/v1/{mount_point}/mfa/method/{method_type}",
            mount_point=mount_point,
            method_type=self.method_type,
        )
        return self._adapter.list(url=api_path)

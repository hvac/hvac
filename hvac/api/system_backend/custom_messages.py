#!/usr/bin/env python
"""Custom messages module."""
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class CustomMessages(SystemBackendMixin):
    """Manage custom messages in the Vault UI.

    Reference doc - https://developer.hashicorp.com/vault/api-docs/system/config-ui-custom-messages
    """

    def list_custom_messages(self):
        """List all custom messages

        Supported methods:
            GET: /sys/config/ui/custom-messages. Produces: 200 application/json
        """
        api_path = "/v1/sys/config/ui/custom-messages"
        return self._adapter.list(
            url=api_path,
        )

    def create_custom_messages(self, title, message, start_time, **kwargs):
        """Create custom message. Optional params passed as kwargs

        Supported methods:
            POST: /sys/config/ui/custom-messages. Produces: 204 (empty body)

        :param title: Title of the custom message.
        :type title: str
        :param message: Message of the custom message.
        :type message: str
        :param start_time: A RFC3339 formatted timestamp that marks the beginning of the custom message's active period.
        :type start_time: str
        """
        params = {
            "title": title,
            "message": message,
            "start_time": start_time,
        }

        for key, value in kwargs.items():
            params[key] = value

        api_path = "/v1/sys/config/ui/custom-messages"
        return self._adapter.post(url=api_path, json=params)

    def delete_custom_messages(self, id):
        """Delete custom message for a given ID

        Supported methods:
            DELETE: /sys/config/ui/custom-messages/:id. Produces: 204 (empty body)

        :param id: ID of the custom message.
        :type id: str
        """
        api_path = f"/v1/sys/config/ui/custom-messages/{id}"
        return self._adapter.delete(
            url=api_path,
        )

    def read_custom_messages(self, id):
        """Read custom message for a given ID

        Supported methods:
            GET: /sys/config/ui/custom-messages/:id. Produces: 200 application/json

        :param id: ID of the custom message
        :type id: str
        """
        api_path = f"/v1/sys/config/ui/custom-messages/{id}"
        return self._adapter.get(
            url=api_path,
        )

    def update_custom_messages(self, id, title, message, start_time, **kwargs):
        """Update custom message for a given ID

        Supported methods:
            POST: /sys/config/ui/custom-messages/:id. Produces: 204 (empty body)

        :param id: ID of the custom message.
        :type id: str
        :param title: Title of the custom message.
        :type title: str
        :param message: Message of the custom message.
        :type message: str
        :param start_time: A RFC3339 formatted timestamp that marks the beginning of the custom message's active period.
        :type start_time: str
        """
        params = {
            "title": title,
            "message": message,
            "start_time": start_time,
        }

        for key, value in kwargs.items():
            params[key] = value

        api_path = f"/v1/sys/config/ui/custom-messages/{id}"
        return self._adapter.post(url=api_path, json=params)

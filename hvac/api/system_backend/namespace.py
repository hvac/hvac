from hvac import utils
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class Namespace(SystemBackendMixin):
    def create_namespace(self, path):
        """Create a namespace at the given path.

        Supported methods:
            POST: /sys/namespaces/{path}. Produces: 200 application/json

        :param path: Path of the namespace to create.
        :type path: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/sys/namespaces/{path}", path=path)
        return self._adapter.post(
            url=api_path,
        )

    def list_namespaces(self):
        """Lists all the namespaces.

        Supported methods:
            LIST: /sys/namespaces. Produces: 200 application/json

        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = "/v1/sys/namespaces/"
        return self._adapter.list(
            url=api_path,
        )

    def read_namespace(self, path):
        """Read the namespace at the given path.

        Supported methods:
            GET: /sys/namespaces/{path}. Produces: 200 application/json

        :param path: Path of the namespace to read.
        :type path: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url("/v1/sys/namespaces/{path}", path=path)
        return self._adapter.get(
            url=api_path,
        )

    def patch_namespace(self, path, custom_metadata=None):
        """Update an existing namespace at the given path.

        If ``custom_metadata`` is omitted, Vault receives an empty patch and silently no-ops.

        Supported methods:
            PATCH: /sys/namespaces/{path}. Produces: 200 application/json

        :param path: Path of the namespace to update.
        :type path: str | unicode
        :param custom_metadata: A map of arbitrary string-to-string valued user-provided metadata meant to describe the namespace.
        :type custom_metadata: dict
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url("/v1/sys/namespaces/{path}", path=path)
        params = utils.remove_nones(
            {
                "custom_metadata": custom_metadata,
            }
        )
        return self._adapter.request(
            method="PATCH",
            url=api_path,
            json=params,
            headers={"Content-Type": "application/merge-patch+json"},
        )

    def delete_namespace(self, path):
        """Delete a namespaces. You cannot delete a namespace with existing child namespaces.

        Supported methods:
            DELETE: /sys/namespaces. Produces: 204 (empty body)

        :param path: Path of the namespace to delete.
        :type path: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/sys/namespaces/{path}", path=path)
        return self._adapter.delete(
            url=api_path,
        )

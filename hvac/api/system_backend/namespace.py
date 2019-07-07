from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class Namespace(SystemBackendMixin):

    def create_namespace(self, path):
        """Create a namespace at the given path.

        Supported methods:
            LIST: /sys/namespaces/{path}. Produces: 200 application/json

        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/sys/namespaces/{path}'.format(path=path)
        response = self._adapter.post(
            url=api_path,
        )
        return response

    def list_namespaces(self):
        """Lists all the namespaces.

        Supported methods:
            LIST: /sys/namespaces. Produces: 200 application/json

        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = '/v1/sys/namespaces/'
        response = self._adapter.list(
            url=api_path,
        )
        return response.json()

from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class License(SystemBackendMixin):
    def read_license_status(self):
        """Read the status of the current Vault Enterprise license.

        Supported methods:
            GET: /sys/license/status. Produces: 200 application/json

        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = "/v1/sys/license/status"
        return self._adapter.get(
            url=api_path,
        )

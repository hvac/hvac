from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class Leader(SystemBackendMixin):

    @property
    def ha_status(self):
        """Read the high availability status and current leader instance of Vault.

        :return: The JSON response returned by read_leader_status()
        :rtype: dict
        """
        return self.read_leader_status()

    def read_leader_status(self):
        """Read the high availability status and current leader instance of Vault.

        Supported methods:
            GET: /sys/leader. Produces: 200 application/json

        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = '/v1/sys/leader'
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

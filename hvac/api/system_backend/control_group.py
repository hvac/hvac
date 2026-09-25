from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class ControlGroup(SystemBackendMixin):
    def authorize_control_group(self, accessor):
        """Authorize a control group request.

        Supported methods:
            POST: /sys/control-group/authorize. Produces: 200 application/json

        :param accessor: The accessor of the token created when the control group request was created.
        :type accessor: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = "/v1/sys/control-group/authorize"
        params = {
            "accessor": accessor,
        }
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def check_control_group_request(self, accessor):
        """Check the status of a control group request.

        Supported methods:
            POST: /sys/control-group/request. Produces: 200 application/json

        :param accessor: The accessor of the token created when the control group request was created.
        :type accessor: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = "/v1/sys/control-group/request"
        params = {
            "accessor": accessor,
        }
        return self._adapter.post(
            url=api_path,
            json=params,
        )

import json
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class Namespace(SystemBackendMixin):

    def create_namespace(self, path):
        """Create a namespace at the given path.

        Supported methods:
            POST: /sys/namespaces/{path}. Produces: 200 application/json

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

    def delete_namespace(self, path):
        """Delete a namespaces. You cannot delete a namespace with existing child namespaces.

        Supported methods:
            DELETE: /sys/namespaces. Produces: 204 (empty body)

        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/sys/namespaces/{path}'.format(path=path)
        response = self._adapter.delete(
            url=api_path,
        )
        return response

    def list_policies_namespace(self, path):
        """List all configured policies in namespaces.

        Supported methods:
            GET: {path}/sys/policy. Produces: 200 application/json

        :param path: Specifies the namespace_name to list policies. This is specified as part of the URL.
        :type path: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = '/v1/{path}/sys/policy'.format(path=path)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    def create_or_update_policy_namespace(self, path, name, policy, pretty_print=True):
        """Add a new or update an existing policy.

        Once a policy is updated, it takes effect immediately to all associated users.

        Supported methods:
            PUT: {path}/sys/policy/{name}. Produces: 204 (empty body)

        :param name: Specifies the name of the policy to create.
        :type name: str | unicode
        :param policy: Specifies the policy document.
        :type policy: str | unicode | dict
        :param path: Specifies the namespace_name to create/update policies. This is specified as part of the URL.
        :type path: str | unicode
        :param pretty_print: If True, and provided a dict for the policy argument, send the policy JSON to Vault with
            "pretty" formatting.
        :type pretty_print: bool
        :return: The response of the request.
        :rtype: requests.Response
        """
        if isinstance(policy, dict):
            if pretty_print:
                policy = json.dumps(policy, indent=4, sort_keys=True)
            else:
                policy = json.dumps(policy)
        params = {
            'policy': policy,
        }
        api_path = '/v1/{path}/sys/policy/{name}'.format(path=path, name=name)
        return self._adapter.put(
            url=api_path,
            json=params,
        )

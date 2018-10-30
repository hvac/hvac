import json

from hvac import exceptions
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin

try:
    import hcl
    has_hcl_parser = True
except ImportError:
    has_hcl_parser = False


class Policy(SystemBackendMixin):

    def list_policies(self):
        """List all configured policies.

        Supported methods:
            GET: /sys/policy. Produces: 200 application/json

        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = '/v1/sys/policy'
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    def read_policy(self, name):
        """Retrieve the policy body for the named policy.

        Supported methods:
            GET: /sys/policy/{name}. Produces: 200 application/json

        :param name: The name of the policy to retrieve.
        :type name: str | unicode
        :return: The response of the request
        :rtype: dict
        """
        api_path = '/v1/sys/policy/{name}'.format(name=name)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    def get_policy(self, name, parse=False):
        """Retrieve the policy body for the named policy.

        :param name: The name of the policy to retrieve.
        :type name: str | unicode
        :param parse: Specifies whether to parse the policy body using pyhcl or not.
        :type parse: bool
        :return: The (optionally parsed) policy body for the specified policy.
        :rtype: str | dict
        """
        try:
            policy = self.read_policy(name=name)['data']['rules']
        except exceptions.InvalidPath:
            return None

        if parse:
            if not has_hcl_parser:
                raise ImportError('pyhcl is required for policy parsing')
            policy = hcl.loads(policy)

        return policy

    def create_or_update_policy(self, name, policy):
        """Add a new or update an existing policy.

        Once a policy is updated, it takes effect immediately to all associated users.

        Supported methods:
            PUT: /sys/policy/{name}. Produces: 204 (empty body)

        :param name: Specifies the name of the policy to create.
        :type name: str | unicode
        :param policy: Specifies the policy document.
        :type policy: str | unicode | dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        if isinstance(policy, dict):
            policy = json.dumps(policy)
        params = {
            'policy': policy,
        }
        api_path = '/v1/sys/policy/{name}'.format(name=name)
        return self._adapter.put(
            url=api_path,
            json=params,
        )

    def delete_policy(self, name):
        """Delete the policy with the given name.

        This will immediately affect all users associated with this policy.

        Supported methods:
            DELETE: /sys/policy/{name}. Produces: 204 (empty body)

        :param name: Specifies the name of the policy to delete.
        :type name: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/sys/policy/{name}'.format(name=name)
        return self._adapter.delete(
            url=api_path,
        )

import json
from hvac import utils
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin
class PasswdPolicy(SystemBackendMixin):
    """
    HVAC does not have password policy so written a module based on ACL polcy.
    """    
    def list_pp_policies(self):
        """
        List all configures password policies. 

        Supported Methos:
            GET: /sys/policies/password?list=true  Produces 200 Application/json

            :return: The Json response of the request
            :rtype: dict
            
        """
        api_path="/sys/policies/password?list=true"
        return self._adaper.get(
            url=api_path,
        )
    
    def get_pp_policies(self,name):
        """
        Retrive the password policy for the names policy

        supported method: GET /sys/policies/password/:name Produces 200 Application/json

            :return: The Json response of the request
            :rtype: dict
            
        """
        api_path = utils.format_url("/sys/policies/password/{name}",name=name)
        return self._adaper.get(
            url=api_path,
        )

    def create_or_update_pp_policy(self,name,policy,pretty_print=True):
        """Add a new or update an existing policy.

        Once a policy is updated, it takes effect immediately to all associated users.

        Supported methods:
            PUT: /sys/policies/password/{name}. Produces: 204 (empty body)

        :param name: Specifies the name of the password policy to create.
        :type name: str | unicode
        :param policy: Specifies the policy document.
        :type policy: str | unicode | dict
        :param pretty_print: If True, and provided a dict for the policy argument, send the policy JSON to Vault with
            "pretty" formatting.
        :type pretty_print: bool
        :return: The response of the request.
        :rtype: requests.Response
        """
        if isinstance(policy,dict):
            if pretty_print:
                policy = json.dumps(policy,indent=4,sort_keys=4)
            else:
                policy = json.dumps(policy)                
        params = {
            "policy": policy
        }
        api_path = utils.format_url(f"/v1/sys/policies/password/{name}", name=name)
        return self._adapter.put(
            url=api_path,
            json=params,
        )
    
    def delete_pp_policy(self,name):
        """
        Delete the password policy with the given name.

        This will immediately affect all users associated with this policy.

        Supported methods:
            DELETE: /sys/policies/password/{name}. Produces: 204 (empty body)

        :param name: Specifies the name of the password policy to delete.
        :type name: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/sys/policies/password/{name}", name=name)
        return self._adapter.delete(
            url=api_path,
        )       
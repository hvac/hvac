from .client import ClientFeature

class TokenRoles(ClientFeature):
    def create(self, role, allowed_policies=None, orphan=None, period=None,
                          renewable=None, path_suffix=None, explicit_max_ttl=None):
        """
        POST /auth/token/roles/<role>
        """
        params = {
            'allowed_policies': allowed_policies,
            'orphan': orphan,
            'period': period,
            'renewable': renewable,
            'path_suffix': path_suffix,
            'explicit_max_ttl': explicit_max_ttl
        }

        return self._post('/v1/auth/token/roles/{0}'.format(role), json=params)

    def get(self, role):
        """
        Returns the named token role.
        """
        return self._read('auth/token/roles/{0}'.format(role))

    def delete(self, role):
        """
        Deletes the named token role.
        """
        return self._delete('auth/token/roles/{0}'.format(role))

    def list(self):
        """
        GET /auth/token/roles?list=true
        """
        return self._list('auth/token/roles')

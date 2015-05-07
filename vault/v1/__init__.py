import requests

from vault import exceptions

def raise_for_status(func):
    def decorator(*args, **kwargs):
        response = func(*args, **kwargs)

        if response.status_code >= 400 and response.status_code < 600:
            errors = response.json().get('errors')

            if response.status_code == 400:
                raise exceptions.InvalidRequest(errors=errors)
            elif response.status_code == 401:
                raise exceptions.Unauthorized(errors=errors)
            elif response.status_code == 404:
                raise exceptions.InvalidPath(errors=errors)
            elif response.status_code == 429:
                raise exceptions.RateLimitExceeded(errors=errors)
            elif response.status_code == 500:
                raise exceptions.InternalServerError(errors=errors)
            elif response.status_code == 503:
                raise exceptions.VaultDown(errors=errors)
            else:
                raise exceptions.UnknownError()

        return response

    return decorator

class Client(object):
    def __init__(self, url, token):
        self._url = url
        self._token = token

    def read(self, path):
        """
        GET /<path>
        """
        return self._get('/v1/{}'.format(path)).json()

    def write(self, path, **kwargs):
        """
        PUT /<path>
        """
        self._put('/v1/{}'.format(path), kwargs)

    def delete(self, path):
        """
        DELETE /<path>
        """
        self._delete('/v1/{}'.format(path))

    def create_token(self, id=None, policies=None, metadata=None,
                     no_parent=False, lease=None, display_name=None,
                     num_uses=None):
        """
        POST /auth/token/create
        """
        params = {
            'id': id,
            'policies': policies,
            'metadata': metadata,
            'no_parent': no_parent,
            'lease': lease,
            'display_name': display_name,
            'num_uses': num_uses,
        }

        return self._post('/v1/auth/token/create', params).json()

    def lookup_token(self, token=None):
        """
        GET /auth/token/lookup/<token>
        GET /auth/token/lookup-self
        """
        if token:
            return self._get('/v1/auth/token/lookup/{}'.format(token)).json()
        else:
            return self._get('/v1/auth/token/lookup-self').json()

    def revoke_token(self, token, orphan=False):
        """
        POST /auth/token/revoke/<token>
        POST /auth/token/revoke-orphan/<token>
        """
        if orphan:
            self._post('/v1/auth/token/revoke-orphan/{}'.format(token))
        else:
            self._post('/v1/auth/token/revoke/{}'.format(token))

    def revoke_token_prefix(self, prefix):
        """
        POST /auth/token/revoke-prefix/<prefix>
        """
        self._post('/v1/auth/token/revoke-prefix/{}'.format(prefix))

    def renew_token(self, token, increment=None):
        """
        POST /auth/token/renew/<token>
        """
        params = {
            'increment': increment,
        }

        return self._post('/v1/auth/token/renew/{}'.format(token), params).json()

    def auth_app_id(self, app_id, user_id, change_to=True, mount_point='app-id'):
        """
        POST /auth/<mount point>/login
        """
        params = {
            'app_id': app_id,
            'user_id': user_id,
        }

        result = self._post('/v1/auth/{}/login'.format(mount_point), params).json()

        if change_to:
            self._token = result['auth']['client_token']

        return result

    def auth_userpass(self, username, password, change_to=True, mount_point='userpass'):
        """
        POST /auth/<mount point>/login/<username>
        """
        params = {
            'password': password,
        }

        result = self._post('/v1/auth/{}/login/{}'.format(mount_point, username), params).json()

        if change_to:
            self._token = result['auth']['client_token']

        return result

    def list_auth_backends(self):
        """
        GET /sys/auth
        """
        return self._get('/v1/sys/auth').json()

    def enable_auth_backend(self, mount_point, auth_type=None, description=None):
        """
        POST /sys/auth/<mount point>
        """
        if not auth_type:
            auth_type = mount_point

        params = {
            'type': auth_type,
            'description': description,
        }

        self._post('/v1/sys/auth/{}'.format(mount_point), params)

    def disable_auth_backend(self, mount_point):
        """
        DELETE /sys/auth/<mount point>
        """
        self._delete('/v1/sys/auth/{}'.format(mount_point))

    @raise_for_status
    def _get(self, url, **kwargs):
        return requests.get(self._url + url, cookies=self._cookies, **kwargs)

    @raise_for_status
    def _post(self, url, data=None, **kwargs):
        return requests.post(self._url + url, json=data, cookies=self._cookies, **kwargs)

    @raise_for_status
    def _put(self, url, data=None, **kwargs):
        return requests.put(self._url + url, json=data, cookies=self._cookies, **kwargs)

    @raise_for_status
    def _delete(self, url, **kwargs):
        return requests.delete(self._url + url, cookies=self._cookies, **kwargs)

    @property
    def _cookies(self):
        return {'token': self._token}

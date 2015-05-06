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
    def _post(self, url, data, **kwargs):
        return requests.post(self._url + url, json=data, cookies=self._cookies, **kwargs)

    @raise_for_status
    def _put(self, url, data, **kwargs):
        return requests.put(self._url + url, json=data, cookies=self._cookies, **kwargs)

    @raise_for_status
    def _delete(self, url, **kwargs):
        return requests.delete(self._url + url, cookies=self._cookies, **kwargs)

    @property
    def _cookies(self):
        return {'token': self._token}

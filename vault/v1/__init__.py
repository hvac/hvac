import requests

class Client(object):
    def __init__(self, url, token):
        self._url = url
        self._cookies = {'token': token}

    def read(self, path):
        return self._get('/v1/{}'.format(path)).json()

    def write(self, path, **kwargs):
        self._put('/v1/{}'.format(path), kwargs)

    def delete(self, path):
        self._delete('/v1/{}'.format(path))

    def _get(self, url, **kwargs):
        url = self._url + url

        response = requests.get(url, cookies=self._cookies, **kwargs)
        response.raise_for_status()

        return response

    def _put(self, url, data, **kwargs):
        url = self._url + url

        response = requests.put(url, json=data, cookies=self._cookies, **kwargs)
        response.raise_for_status()

        return response

    def _delete(self, url, **kwargs):
        url = self._url + url

        response = requests.delete(url, cookies=self._cookies, **kwargs)
        response.raise_for_status()

        return response

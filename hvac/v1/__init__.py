import requests

from hvac import exceptions

class Client(object):
    def __init__(self, url=None, token=None, cert=None, verify=True):
        if not url:
            url = 'http://localhost:8200'

        self._url = url

        self._cert = cert
        self._verify = verify

        self.token = token

    def read(self, path):
        """
        GET /<path>
        """
        try:
            return self._get('/v1/{}'.format(path)).json()
        except exceptions.InvalidPath:
            return None

    def write(self, path, **kwargs):
        """
        PUT /<path>
        """
        response = self._put('/v1/{}'.format(path), json=kwargs)

        if response.status_code == 200:
            return response.json()

    def delete(self, path):
        """
        DELETE /<path>
        """
        self._delete('/v1/{}'.format(path))

    def is_initialized(self):
        """
        GET /sys/init
        """
        return self._get('/v1/sys/init').json()['initialized']

    def initialize(self, secret_shares=5, secret_threshold=3, pgp_keys=None):
        """
        PUT /sys/init
        """
        params = {
            'secret_shares': secret_shares,
            'secret_threshold': secret_threshold,
        }

        if pgp_keys:
            if len(pgp_keys) != secret_shares:
                raise ValueError('Length of pgp_keys must equal secret shares')

            params['pgp_keys'] = pgp_keys

        return self._put('/v1/sys/init', json=params).json()

    @property
    def seal_status(self):
        """
        GET /sys/seal-status
        """
        return self._get('/v1/sys/seal-status').json()

    def is_sealed(self):
        return self.seal_status['sealed']

    def seal(self):
        """
        PUT /sys/seal
        """
        self._put('/v1/sys/seal')

    def unseal(self, key):
        """
        PUT /sys/unseal
        """
        params = {
            'key': key,
        }

        return self._put('/v1/sys/unseal', json=params).json()

    def unseal_multi(self, keys):
        result = None

        for key in keys:
            result = self.unseal(key)
            if not result['sealed']:
                break

        return result

    @property
    def key_status(self):
        """
        GET /sys/key-status
        """
        return self._get('/v1/sys/key-status').json()

    def rotate(self):
        """
        PUT /sys/rotate
        """
        self._put('/v1/sys/rotate')

    @property
    def rekey_status(self):
        """
        GET /sys/rekey/init
        """
        return self._get('/v1/sys/rekey/init').json()

    def start_rekey(self, secret_shares=5, secret_threshold=3):
        """
        PUT /sys/rekey/init
        """
        params = {
            'secret_shares': secret_shares,
            'secret_threshold': secret_threshold,
        }

        self._put('/v1/sys/rekey/init', json=params)

    def cancel_rekey(self):
        """
        DELETE /sys/rekey/init
        """
        self._delete('/v1/sys/rekey/init')

    def rekey(self, key):
        """
        PUT /sys/rekey/update
        """
        params = {
            'key': key,
        }

        return self._put('/v1/sys/rekey/update', json=params).json()

    @property
    def ha_status(self):
        """
        GET /sys/leader
        """
        return self._get('/v1/sys/leader').json()

    def renew_secret(self, lease_id):
        """
        PUT /sys/renew/<lease id>
        """
        return self._put('/v1/sys/renew/{}'.format(lease_id)).json()

    def revoke_secret(self, lease_id):
        """
        PUT /sys/revoke/<lease id>
        """
        self._put('/v1/sys/revoke/{}'.format(lease_id))

    def revoke_secret_prefix(self, path_prefix):
        """
        PUT /sys/revoke-prefix/<path prefix>
        """
        self._put('/v1/sys/revoke-prefix/{}'.format(path_prefix))

    def list_secret_backends(self):
        """
        GET /sys/mounts
        """
        return self._get('/v1/sys/mounts').json()

    def enable_secret_backend(self, backend_type, description=None, mount_point=None, config=None):
        """
        POST /sys/auth/<mount point>
        """
        if not mount_point:
            mount_point = backend_type

        params = {
            'type': backend_type,
            'description': description,
            'config': config,
        }

        self._post('/v1/sys/mounts/{}'.format(mount_point), json=params)

    def disable_secret_backend(self, mount_point):
        """
        DELETE /sys/mounts/<mount point>
        """
        self._delete('/v1/sys/mounts/{}'.format(mount_point))

    def remount_secret_backend(self, from_mount_point, to_mount_point):
        """
        POST /sys/remount
        """
        params = {
            'from': from_mount_point,
            'to': to_mount_point,
        }

        self._post('/v1/sys/remount', json=params)

    def list_policies(self):
        """
        GET /sys/policy
        """
        return self._get('/v1/sys/policy').json()['policies']

    def set_policy(self, name, rules):
        """
        PUT /sys/policy/<name>
        """
        params = {
            'rules': rules,
        }

        self._put('/v1/sys/policy/{}'.format(name), json=params)

    def delete_policy(self, name):
        """
        DELETE /sys/policy/<name>
        """
        self._delete('/v1/sys/policy/{}'.format(name))

    def list_audit_backends(self):
        """
        GET /sys/audit
        """
        return self._get('/v1/sys/audit').json()

    def enable_audit_backend(self, backend_type, description=None, options=None, name=None):
        """
        POST /sys/audit/<name>
        """
        if not name:
            name = backend_type

        params = {
            'type': backend_type,
            'description': description,
            'options': options,
        }

        self._post('/v1/sys/audit/{}'.format(name), json=params)

    def disable_audit_backend(self, name):
        """
        DELETE /sys/audit/<name>
        """
        self._delete('/v1/sys/audit/{}'.format(name))

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

        return self._post('/v1/auth/token/create', json=params).json()

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

        return self._post('/v1/auth/token/renew/{}'.format(token), json=params).json()

    def logout(self):
        """
        Clears the token used for authentication
        """
        self.token = None

    def is_authenticated(self):
        """
        Helper method which returns the authentication status of the client
        """
        if not self.token:
            return False

        try:
            self.lookup_token()
            return True
        except exceptions.Forbidden:
            return False
        except exceptions.InvalidPath:
            return False

    def auth_app_id(self, app_id, user_id, mount_point='app-id', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        params = {
            'app_id': app_id,
            'user_id': user_id,
        }

        return self.auth('/v1/auth/{}/login'.format(mount_point), json=params, use_token=use_token)

    def auth_tls(self, mount_point='cert', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        return self.auth('/v1/auth/{}/login'.format(mount_point), use_token=use_token)

    def auth_userpass(self, username, password, mount_point='userpass', use_token=True, **kwargs):
        """
        POST /auth/<mount point>/login/<username>
        """
        params = {
            'password': password,
        }

        params.update(kwargs)

        return self.auth('/v1/auth/{}/login/{}'.format(mount_point, username), json=params, use_token=use_token)

    def auth_ldap(self, username, password, mount_point='ldap', use_token=True, **kwargs):
        """
        POST /auth/<mount point>/login/<username>
        """
        params = {
            'password': password,
        }

        params.update(kwargs)

        return self.auth('/v1/auth/{}/login/{}'.format(mount_point, username), json=params, use_token=use_token)

    def auth_github(self, token, mount_point='github', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        params = {
            'token': token,
        }

        return self.auth('/v1/auth/{}/login'.format(mount_point), json=params, use_token=use_token)

    def auth(self, url, use_token=True, **kwargs):
        response = self._post(url, **kwargs).json()

        if use_token:
            self.token = response['auth']['client_token']

        return response

    def list_auth_backends(self):
        """
        GET /sys/auth
        """
        return self._get('/v1/sys/auth').json()

    def enable_auth_backend(self, backend_type, description=None, mount_point=None):
        """
        POST /sys/auth/<mount point>
        """
        if not mount_point:
            mount_point = backend_type

        params = {
            'type': backend_type,
            'description': description,
        }

        self._post('/v1/sys/auth/{}'.format(mount_point), json=params)

    def disable_auth_backend(self, mount_point):
        """
        DELETE /sys/auth/<mount point>
        """
        self._delete('/v1/sys/auth/{}'.format(mount_point))

    def _get(self, url, **kwargs):
        return self.__request('get', url, **kwargs)

    def _post(self, url, **kwargs):
        return self.__request('post', url, **kwargs)

    def _put(self, url, **kwargs):
        return self.__request('put', url, **kwargs)

    def _delete(self, url, **kwargs):
        return self.__request('delete', url, **kwargs)

    def __request(self, method, url, headers=None, **kwargs):
        url = self._url + url

        if not headers:
            headers = {}

        if self.token:
            headers['X-Vault-Token'] = self.token

        response = requests.request(method,
                                    url,
                                    cert=self._cert,
                                    verify=self._verify,
                                    headers=headers,
                                    **kwargs)

        if response.status_code >= 400 and response.status_code < 600:
            errors = response.json().get('errors')

            if response.status_code == 400:
                raise exceptions.InvalidRequest(errors=errors)
            elif response.status_code == 401:
                raise exceptions.Unauthorized(errors=errors)
            elif response.status_code == 403:
                raise exceptions.Forbidden(errors=errors)
            elif response.status_code == 404:
                raise exceptions.InvalidPath(errors=errors)
            elif response.status_code == 429:
                raise exceptions.RateLimitExceeded(errors=errors)
            elif response.status_code == 500:
                raise exceptions.InternalServerError(errors=errors)
            elif response.status_code == 503:
                raise exceptions.VaultDown(errors=errors)
            else:
                raise exceptions.UnexpectedError()

        return response

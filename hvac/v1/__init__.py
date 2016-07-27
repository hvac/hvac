from __future__ import unicode_literals

import json

try:
    import hcl
    has_hcl_parser = True
except ImportError:
    has_hcl_parser = False
import requests

from hvac import exceptions

try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin

class Client(object):
    def __init__(self, url='http://localhost:8200', token=None,
                 cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None):

        if not session:
            session = requests.Session()

        self.allow_redirects = allow_redirects
        self.session = session
        self.token = token

        self._url = url
        self._kwargs = {
            'cert': cert,
            'verify': verify,
            'timeout': timeout,
            'proxies': proxies,
        }

    def read(self, path, wrap_ttl=None):
        """
        GET /<path>
        """
        try:
            return self._get('/v1/{0}'.format(path), wrap_ttl=wrap_ttl).json()
        except exceptions.InvalidPath:
            return None

    def list(self, path):
        """
        GET /<path>?list=true
        """
        try:
            payload = {
                'list': True
            }
            return self._get('/v1/{}'.format(path), params=payload).json()
        except exceptions.InvalidPath:
            return None

    def write(self, path, **kwargs):
        """
        PUT /<path>
        """
        response = self._put('/v1/{0}'.format(path), json=kwargs)

        if response.status_code == 200:
            return response.json()

    def delete(self, path):
        """
        DELETE /<path>
        """
        self._delete('/v1/{0}'.format(path))

    def unwrap(self, token):
        """
        GET /cubbyhole/response
        X-Vault-Token: <token>
        """
        path = "cubbyhole/response"
        _token = self.token
        try:
            self.token = token
            return json.loads(self.read(path)['data']['response'])
        finally:
            self.token = _token

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

    def start_rekey(self, secret_shares=5, secret_threshold=3, pgp_keys=None,
                    backup=False):
        """
        PUT /sys/rekey/init
        """
        params = {
            'secret_shares': secret_shares,
            'secret_threshold': secret_threshold,
        }

        if pgp_keys:
            if len(pgp_keys) != secret_shares:
                raise ValueError('Length of pgp_keys must equal secret shares')

            params['pgp_keys'] = pgp_keys
            params['backup'] = backup

        resp = self._put('/v1/sys/rekey/init', json=params)
        if resp.text:
            return resp.json()

    def cancel_rekey(self):
        """
        DELETE /sys/rekey/init
        """
        self._delete('/v1/sys/rekey/init')

    def rekey(self, key, nonce=None):
        """
        PUT /sys/rekey/update
        """
        params = {
            'key': key,
        }

        if nonce:
            params['nonce'] = nonce

        return self._put('/v1/sys/rekey/update', json=params).json()

    def rekey_multi(self, keys, nonce=None):
        result = None

        for key in keys:
            result = self.rekey(key, nonce=nonce)
            if result['complete']:
                break

        return result

    def get_backed_up_keys(self):
        """
        GET /sys/rekey/backup
        """
        return self._get('/v1/sys/rekey/backup').json()

    @property
    def ha_status(self):
        """
        GET /sys/leader
        """
        return self._get('/v1/sys/leader').json()

    def renew_secret(self, lease_id, increment=None):
        """
        PUT /sys/renew/<lease id>
        """
        params = {
            'increment': increment,
        }
        return self._post('/v1/sys/renew/{0}'.format(lease_id), json=params).json()

    def revoke_secret(self, lease_id):
        """
        PUT /sys/revoke/<lease id>
        """
        self._put('/v1/sys/revoke/{0}'.format(lease_id))

    def revoke_secret_prefix(self, path_prefix):
        """
        PUT /sys/revoke-prefix/<path prefix>
        """
        self._put('/v1/sys/revoke-prefix/{0}'.format(path_prefix))

    def revoke_self_token(self):
        """
        PUT /auth/token/revoke-self
        """
        self._put('/v1/auth/token/revoke-self')

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

        self._post('/v1/sys/mounts/{0}'.format(mount_point), json=params)

    def disable_secret_backend(self, mount_point):
        """
        DELETE /sys/mounts/<mount point>
        """
        self._delete('/v1/sys/mounts/{0}'.format(mount_point))

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

    def get_policy(self, name, parse=False):
        """
        GET /sys/policy/<name>
        """
        try:
            policy = self._get('/v1/sys/policy/{0}'.format(name)).json()['rules']
            if parse:
                if not has_hcl_parser:
                    raise ImportError('pyhcl is required for policy parsing')

                policy = hcl.loads(policy)

            return policy
        except exceptions.InvalidPath:
            return None

    def set_policy(self, name, rules):
        """
        PUT /sys/policy/<name>
        """

        if isinstance(rules, dict):
            rules = json.dumps(rules)

        params = {
            'rules': rules,
        }

        self._put('/v1/sys/policy/{0}'.format(name), json=params)

    def delete_policy(self, name):
        """
        DELETE /sys/policy/<name>
        """
        self._delete('/v1/sys/policy/{0}'.format(name))

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

        self._post('/v1/sys/audit/{0}'.format(name), json=params)

    def disable_audit_backend(self, name):
        """
        DELETE /sys/audit/<name>
        """
        self._delete('/v1/sys/audit/{0}'.format(name))

    def audit_hash(self, name, input):
        """
        POST /sys/audit-hash
        """
        params = {
            'input': input,
        }
        return self._post('/v1/sys/audit-hash/{0}'.format(name), json=params).json()

    def create_token(self, id=None, policies=None, meta=None,
                     no_parent=False, lease=None, display_name=None,
                     num_uses=None, no_default_policy=False,
                     ttl=None, orphan=False, wrap_ttl=None):
        """
        POST /auth/token/create
        POST /auth/token/create-orphan
        """
        params = {
            'id': id,
            'policies': policies,
            'meta': meta,
            'no_parent': no_parent,
            'display_name': display_name,
            'num_uses': num_uses,
            'no_default_policy': no_default_policy,
        }

        if lease:
            params['lease'] = lease
        else:
            params['ttl'] = ttl

        if orphan:
            return self._post('/v1/auth/token/create-orphan', json=params, wrap_ttl=wrap_ttl).json()
        else:
            return self._post('/v1/auth/token/create', json=params, wrap_ttl=wrap_ttl).json()

    def lookup_token(self, token=None, accessor=False, wrap_ttl=None):
        """
        GET /auth/token/lookup/<token>
        GET /auth/token/lookup-accessor/<token-accessor>
        GET /auth/token/lookup-self
        """
        if token:
            if accessor:
                path = '/v1/auth/token/lookup-accessor/{0}'.format(token)
                return self._post(path, wrap_ttl=wrap_ttl).json()
            else:
                return self._get('/v1/auth/token/lookup/{0}'.format(token)).json()
        else:
            return self._get('/v1/auth/token/lookup-self', wrap_ttl=wrap_ttl).json()

    def revoke_token(self, token, orphan=False, accessor=False):
        """
        POST /auth/token/revoke/<token>
        POST /auth/token/revoke-orphan/<token>
        POST /auth/token/revoke-accessor/<token-accessor>
        """
        if accessor and orphan:
            msg = "revoke_token does not support 'orphan' and 'accessor' flags together"
            raise exceptions.InvalidRequest(msg)
        elif accessor:
            self._post('/v1/auth/token/revoke-accessor/{0}'.format(token))
        elif orphan:
            self._post('/v1/auth/token/revoke-orphan/{0}'.format(token))
        else:
            self._post('/v1/auth/token/revoke/{0}'.format(token))

    def revoke_token_prefix(self, prefix):
        """
        POST /auth/token/revoke-prefix/<prefix>
        """
        self._post('/v1/auth/token/revoke-prefix/{0}'.format(prefix))

    def renew_token(self, token=None, increment=None, wrap_ttl=None):
        """
        POST /auth/token/renew/<token>
        POST /auth/token/renew-self
        """
        params = {
            'increment': increment,
        }

        if token:
            path = '/v1/auth/token/renew/{0}'.format(token)
            return self._post(path, json=params, wrap_ttl=wrap_ttl).json()
        else:
            return self._post('/v1/auth/token/renew-self', json=params, wrap_ttl=wrap_ttl).json()

    def logout(self, revoke_token=False):
        """
        Clears the token used for authentication, optionally revoking it before doing so
        """
        if revoke_token:
            self.revoke_self_token()

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
        except exceptions.InvalidRequest:
            return False

    def auth_app_id(self, app_id, user_id, mount_point='app-id', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        params = {
            'app_id': app_id,
            'user_id': user_id,
        }

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def auth_tls(self, mount_point='cert', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        return self.auth('/v1/auth/{0}/login'.format(mount_point), use_token=use_token)

    def auth_userpass(self, username, password, mount_point='userpass', use_token=True, **kwargs):
        """
        POST /auth/<mount point>/login/<username>
        """
        params = {
            'password': password,
        }

        params.update(kwargs)

        return self.auth('/v1/auth/{0}/login/{1}'.format(mount_point, username), json=params, use_token=use_token)

    def auth_ec2(self, pkcs7, nonce=None, role=None, use_token=True):
        """
        POST /auth/aws-ec2/login
        """
        params = {'pkcs7': pkcs7}
        if nonce:
            params['nonce'] = nonce
        if role:
            params['role'] = role

        return self.auth('/v1/auth/aws-ec2/login', json=params, use_token=use_token).json()

    def create_userpass(self, username, password, policies, mount_point='userpass', **kwargs):
        """
        POST /auth/<mount point>/users/<username>
        """

        # Users can have more than 1 policy. It is easier for the user to pass in the
        # policies as a list so if they do, we need to convert to a , delimited string.
        if isinstance(policies, (list, set, tuple)):
            policies = ','.join(policies)

        params = {
            'password': password,
            'policies': policies
        }
        params.update(kwargs)

        return self._post('/v1/auth/{}/users/{}'.format(mount_point, username), json=params)

    def delete_userpass(self, username, mount_point='userpass'):
        """
        DELETE /auth/<mount point>/users/<username>
        """
        return self._delete('/v1/auth/{}/users/{}'.format(mount_point, username))

    def create_app_id(self, app_id, policies, display_name=None, mount_point='app-id', **kwargs):
        """
        POST /auth/<mount point>/map/app-id/<app_id>
        """

        # app-id can have more than 1 policy. It is easier for the user to pass in the
        # policies as a list so if they do, we need to convert to a , delimited string.
        if isinstance(policies, (list, set, tuple)):
            policies = ','.join(policies)

        params = {
            'value': policies
        }

        # Only use the display_name if it has a value. Made it a named param for user
        # convienence instead of leaving it as part of the kwargs
        if display_name:
            params['display_name'] = display_name

        params.update(kwargs)

        return self._post('/v1/auth/{}/map/app-id/{}'.format(mount_point, app_id), json=params)

    def get_app_id(self, app_id, mount_point='app-id', wrap_ttl=None):
        """
        GET /auth/<mount_point>/map/app-id/<app_id>
        """
        path = '/v1/auth/{0}/map/app-id/{1}'.format(mount_point, app_id)
        return self._get(path, wrap_ttl=wrap_ttl).json()

    def delete_app_id(self, app_id, mount_point='app-id'):
        """
        DELETE /auth/<mount_point>/map/app-id/<app_id>
        """
        return self._delete('/v1/auth/{0}/map/app-id/{1}'.format(mount_point, app_id))

    def create_user_id(self, user_id, app_id, cidr_block=None, mount_point='app-id', **kwargs):
        """
        POST /auth/<mount point>/map/user-id/<user_id>
        """

        # user-id can be associated to more than 1 app-id (aka policy). It is easier for the user to
        # pass in the policies as a list so if they do, we need to convert to a , delimited string.
        if isinstance(app_id, (list, set, tuple)):
            app_id = ','.join(app_id)

        params = {
            'value': app_id
        }

        # Only use the cidr_block if it has a value. Made it a named param for user
        # convienence instead of leaving it as part of the kwargs
        if cidr_block:
            params['cidr_block'] = cidr_block

        params.update(kwargs)

        return self._post('/v1/auth/{}/map/user-id/{}'.format(mount_point, user_id), json=params)

    def get_user_id(self, user_id, mount_point='app-id', wrap_ttl=None):
        """
        GET /auth/<mount_point>/map/user-id/<user_id>
        """
        path = '/v1/auth/{0}/map/user-id/{1}'.format(mount_point, user_id)
        return self._get(path, wrap_ttl=wrap_ttl).json()

    def delete_user_id(self, user_id, mount_point='app-id'):
        """
        DELETE /auth/<mount_point>/map/user-id/<user_id>
        """
        return self._delete('/v1/auth/{0}/map/user-id/{1}'.format(mount_point, user_id))

    def create_vault_ec2_client_configuration(self, access_key, secret_key, endpoint=None):
        """
        POST /auth/aws-ec2/config/client
        """
        params = {
            'access_key': access_key,
            'secret_key': secret_key
        }
        if endpoint is not None:
            params['endpoint'] = endpoint

        return self._post('/v1/auth/aws-ec2/config/client', json=params)

    def get_vault_ec2_client_configuration(self):
        """
        GET /auth/aws-ec2/config/client
        """
        return self._get('/v1/auth/aws-ec2/config/client').json()

    def delete_vault_ec2_client_configuration(self):
        """
        DELETE /auth/aws-ec2/config/client
        """
        return self._delete('/v1/auth/aws-ec2/config/client')

    def create_vault_ec2_certificate_configuration(self, cert_name, aws_public_cert):
        """
        POST /auth/aws-ec2/config/certificate/<cert_name>
        """
        params = {
            'cert_name': cert_name,
            'aws_public_cert': aws_public_cert
        }
        return self._post('/v1/auth/aws-ec2/config/certificate/{0}'.format(cert_name), json=params)

    def get_vault_ec2_certificate_configuration(self, cert_name):
        """
        GET /auth/aws-ec2/config/certificate/<cert_name>
        """
        return self._get('/v1/auth/aws-ec2/config/certificate/{0}'.format(cert_name)).json()

    def list_vault_ec2_certificate_configurations(self):
        """
        GET /auth/aws-ec2/config/certificates?list=true
        """
        params = {'list': True}
        return self._get('/v1/auth/aws-ec2/config/certificates', params=params).json()

    def create_ec2_role(self, role, bound_ami_id, role_tag=None, max_ttl=None, policies=None,
                          allow_instance_migration=False, disallow_reauthentication=False, **kwargs):
        """
        POST /auth/aws-ec2/role/<role>
        """
        params = {
            'role': role,
            'bound_ami_id': bound_ami_id,
            'disallow_reauthentication': disallow_reauthentication,
            'allow_instance_migration': allow_instance_migration
        }
        if role_tag is not None:
            params['role_tag'] = role_tag
        if max_ttl is not None:
            params['max_ttl'] = max_ttl
        if policies is not None:
            params['policies'] = policies
        params.update(**kwargs)
        return self._post('/v1/auth/aws-ec2/role/{0}'.format(role), json=params)

    def get_ec2_role(self, role):
        """
        GET /auth/aws-ec2/role/<role>
        """
        return self._get('/v1/auth/aws-ec2/role/{0}'.format(role)).json()

    def delete_ec2_role(self, role):
        """
        DELETE /auth/aws-ec2/role/<role>
        """
        return self._delete('/v1/auth/aws-ec2/role/{0}'.format(role))

    def list_ec2_roles(self):
        """
        GET /auth/aws-ec2/roles?list=true
        """
        return self._get('/v1/auth/aws-ec2/roles', params={'list': True})

    def create_ec2_role_tag(self, role, policies=None, max_ttl=None, instance_id=None,
                            disallow_reauthentication=False, allow_instance_migration=False):
        """
        POST /auth/aws-ec2/role/<role>/tag
        """
        params = {
            'role': role,
            'disallow_reauthentication': disallow_reauthentication,
            'allow_instance_migration': allow_instance_migration
        }
        if max_ttl is not None:
            params['max_ttl'] = max_ttl
        if policies is not None:
            params['policies'] = policies
        if instance_id is not None:
            params['instance_id'] = instance_id
        return self._post('/v1/auth/aws-ec2/role/{0}/tag'.format(role), json=params).json()

    def auth_ldap(self, username, password, mount_point='ldap', use_token=True, **kwargs):
        """
        POST /auth/<mount point>/login/<username>
        """
        params = {
            'password': password,
        }

        params.update(kwargs)

        return self.auth('/v1/auth/{0}/login/{1}'.format(mount_point, username), json=params, use_token=use_token)

    def auth_github(self, token, mount_point='github', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        params = {
            'token': token,
        }

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

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

        self._post('/v1/sys/auth/{0}'.format(mount_point), json=params)

    def disable_auth_backend(self, mount_point):
        """
        DELETE /sys/auth/<mount point>
        """
        self._delete('/v1/sys/auth/{0}'.format(mount_point))

    def close(self):
        """
        Close the underlying Requests session
        """
        self.session.close()

    def _get(self, url, **kwargs):
        return self.__request('get', url, **kwargs)

    def _post(self, url, **kwargs):
        return self.__request('post', url, **kwargs)

    def _put(self, url, **kwargs):
        return self.__request('put', url, **kwargs)

    def _delete(self, url, **kwargs):
        return self.__request('delete', url, **kwargs)

    def __request(self, method, url, headers=None, **kwargs):
        url = urljoin(self._url, url)

        if not headers:
            headers = {}

        if self.token:
            headers['X-Vault-Token'] = self.token

        wrap_ttl = kwargs.pop('wrap_ttl', None)
        if wrap_ttl:
            headers['X-Vault-Wrap-TTL'] = str(wrap_ttl)

        _kwargs = self._kwargs.copy()
        _kwargs.update(kwargs)

        response = self.session.request(method, url, headers=headers,
                                        allow_redirects=False, **_kwargs)

        # NOTE(ianunruh): workaround for https://github.com/ianunruh/hvac/issues/51
        while response.is_redirect and self.allow_redirects:
            url = urljoin(self._url, response.headers['Location'])
            response = self.session.request(method, url, headers=headers,
                                            allow_redirects=False, **_kwargs)

        if response.status_code >= 400 and response.status_code < 600:
            text = errors = None
            if response.headers.get('Content-Type') == 'application/json':
                errors = response.json().get('errors')
            if errors is None:
                text = response.text
            self.__raise_error(response.status_code, text, errors=errors)

        return response

    def __raise_error(self, status_code, message=None, errors=None):
        if status_code == 400:
            raise exceptions.InvalidRequest(message, errors=errors)
        elif status_code == 401:
            raise exceptions.Unauthorized(message, errors=errors)
        elif status_code == 403:
            raise exceptions.Forbidden(message, errors=errors)
        elif status_code == 404:
            raise exceptions.InvalidPath(message, errors=errors)
        elif status_code == 429:
            raise exceptions.RateLimitExceeded(message, errors=errors)
        elif status_code == 500:
            raise exceptions.InternalServerError(message, errors=errors)
        elif status_code == 503:
            raise exceptions.VaultDown(message, errors=errors)
        else:
            raise exceptions.UnexpectedError(message)

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

    def write(self, path, wrap_ttl=None, **kwargs):
        """
        PUT /<path>
        """
        response = self._put('/v1/{0}'.format(path), json=kwargs, wrap_ttl=wrap_ttl)

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

    def unseal_reset(self):
        """
        PUT /sys/unseal
        """
        params = {
            'reset': True,
        }
        return self._put('/v1/sys/unseal', json=params).json()

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
            if 'complete' in result and result['complete']:
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
        PUT /sys/leases/renew
        """
        params = {
            'lease_id': lease_id,
            'increment': increment,
        }
        return self._put('/v1/sys/leases/renew', json=params).json()

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

    def tune_secret_backend(self, backend_type, mount_point=None, default_lease_ttl=None, max_lease_ttl=None):
        """
        POST /sys/mounts/<mount point>/tune
        """

        if not mount_point:
            mount_point = backend_type

        params = {
            'default_lease_ttl': default_lease_ttl,
            'max_lease_ttl': max_lease_ttl
        }

        self._post('/v1/sys/mounts/{0}/tune'.format(mount_point), json=params)

    def get_secret_backend_tuning(self, backend_type, mount_point=None):
        """
        GET /sys/mounts/<mount point>/tune
        """
        if not mount_point:
            mount_point = backend_type

        return self._get('/v1/sys/mounts/{0}/tune'.format(mount_point)).json()

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

    def create_token(self, role=None, token_id=None, policies=None, meta=None,
                     no_parent=False, lease=None, display_name=None,
                     num_uses=None, no_default_policy=False,
                     ttl=None, orphan=False, wrap_ttl=None, renewable=None,
                     explicit_max_ttl=None, period=None):
        """
        POST /auth/token/create
        POST /auth/token/create/<role>
        POST /auth/token/create-orphan
        """
        params = {
            'id': token_id,
            'policies': policies,
            'meta': meta,
            'no_parent': no_parent,
            'display_name': display_name,
            'num_uses': num_uses,
            'no_default_policy': no_default_policy,
            'renewable': renewable
        }

        if lease:
            params['lease'] = lease
        else:
            params['ttl'] = ttl
            params['explicit_max_ttl'] = explicit_max_ttl

        if explicit_max_ttl:
            params['explicit_max_ttl'] = explicit_max_ttl

        if period:
            params['period'] = period

        if orphan:
            return self._post('/v1/auth/token/create-orphan', json=params, wrap_ttl=wrap_ttl).json()
        elif role:
            return self._post('/v1/auth/token/create/{0}'.format(role), json=params, wrap_ttl=wrap_ttl).json()
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

    def create_token_role(self, role,
                          allowed_policies=None, disallowed_policies=None,
                          orphan=None, period=None, renewable=None,
                          path_suffix=None, explicit_max_ttl=None):
        """
        POST /auth/token/roles/<role>
        """
        params = {
            'allowed_policies': allowed_policies,
            'disallowed_policies': disallowed_policies,
            'orphan': orphan,
            'period': period,
            'renewable': renewable,
            'path_suffix': path_suffix,
            'explicit_max_ttl': explicit_max_ttl
        }
        return self._post('/v1/auth/token/roles/{0}'.format(role), json=params)

    def token_role(self, role):
        """
        Returns the named token role.
        """
        return self.read('auth/token/roles/{0}'.format(role))

    def delete_token_role(self, role):
        """
        Deletes the named token role.
        """
        return self.delete('auth/token/roles/{0}'.format(role))

    def list_token_roles(self):
        """
        GET /auth/token/roles?list=true
        """
        return self.list('auth/token/roles')

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

    def create_ec2_role(self, role, bound_ami_id=None, bound_account_id=None, bound_iam_role_arn=None,
                        bound_iam_instance_profile_arn=None, role_tag=None, max_ttl=None, policies=None,
                        allow_instance_migration=False, disallow_reauthentication=False, **kwargs):
        """
        POST /auth/aws-ec2/role/<role>
        """
        params = {
            'role': role,
            'disallow_reauthentication': disallow_reauthentication,
            'allow_instance_migration': allow_instance_migration
        }
        if bound_ami_id is not None:
            params['bound_ami_id'] = bound_ami_id
        if bound_account_id is not None:
            params['bound_account_id'] = bound_account_id
        if bound_iam_role_arn is not None:
            params['bound_iam_role_arn'] = bound_iam_role_arn
        if bound_iam_instance_profile_arn is not None:
            params['bound_iam_instance_profile_arn'] = bound_iam_instance_profile_arn
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
        try:
            return self._get('/v1/auth/aws-ec2/roles', params={'list': True}).json()
        except exceptions.InvalidPath:
            return None

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

    def create_role(self, role_name, **kwargs):
        """
        POST /auth/approle/role/<role name>
        """

        self._post('/v1/auth/approle/role/{0}'.format(role_name), json=kwargs)

    def list_roles(self):
        """
        GET /auth/approle/role
        """

        return self._get('/v1/auth/approle/role?list=true').json()

    def get_role_id(self, role_name):
        """
        GET /auth/approle/role/<role name>/role-id
        """

        url = '/v1/auth/approle/role/{0}/role-id'.format(role_name)
        return self._get(url).json()['data']['role_id']

    def set_role_id(self, role_name, role_id):
        """
        POST /auth/approle/role/<role name>/role-id
        """

        url = '/v1/auth/approle/role/{0}/role-id'.format(role_name)
        params = {
            'role_id': role_id
        }
        self._post(url, json=params)


    def get_role(self, role_name):
        """
        GET /auth/approle/role/<role name>
        """
        return self._get('/v1/auth/approle/role/{0}'.format(role_name)).json()

    def create_role_secret_id(self, role_name, meta=None, cidr_list=None):
        """
        POST /auth/approle/role/<role name>/secret-id
        """

        url = '/v1/auth/approle/role/{0}/secret-id'.format(role_name)
        params = {}
        if meta is not None:
            params['metadata'] = json.dumps(meta)
        if cidr_list is not None:
            params['cidr_list'] = cidr_list
        return self._post(url, json=params).json()

    def get_role_secret_id(self, role_name, secret_id):
        """
        POST /auth/approle/role/<role name>/secret-id/lookup
        """
        url = '/v1/auth/approle/role/{0}/secret-id/lookup'.format(role_name)
        params = {
            'secret_id': secret_id
        }
        return self._post(url, json=params).json()

    def list_role_secrets(self, role_name):
        """
        GET /auth/approle/role/<role name>/secret-id?list=true
        """
        url = '/v1/auth/approle/role/{0}/secret-id?list=true'.format(role_name)
        return self._get(url).json()

    def get_role_secret_id_accessor(self, role_name, secret_id_accessor):
        """
        GET /auth/approle/role/<role name>/secret-id-accessor/<secret_id_accessor>
        """
        url = '/v1/auth/approle/role/{0}/secret-id-accessor/{1}'.format(role_name, secret_id_accessor)
        return self._get(url).json()

    def delete_role_secret_id(self, role_name, secret_id):
        """
        POST /auth/approle/role/<role name>/secret-id/destroy
        """
        url = '/v1/auth/approle/role/{0}/secret-id/destroy'.format(role_name)
        params = {
            'secret_id': secret_id
        }
        self._post(url, json=params)

    def delete_role_secret_id_accessor(self, role_name, secret_id_accessor):
        """
        DELETE /auth/approle/role/<role name>/secret-id/<secret_id_accessor>
        """
        url = '/v1/auth/approle/role/{0}/secret-id-accessor/{1}'.format(role_name, secret_id_accessor)
        self._delete(url)

    def create_role_custom_secret_id(self, role_name, secret_id, meta=None):
        """
        POST /auth/approle/role/<role name>/custom-secret-id
        """
        url = '/v1/auth/approle/role/{0}/custom-secret-id'.format(role_name)
        params = {
            'secret_id': secret_id
        }
        if meta is not None:
            params['meta'] = meta
        return self._post(url, json=params).json()

    def auth_approle(self, role_id, secret_id=None, mount_point='approle', use_token=True):
        """
        POST /auth/approle/login
        """
        params = {
            'role_id': role_id
        }
        if secret_id is not None:
            params['secret_id'] = secret_id

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def transit_create_key(self, name, convergent_encryption=None, derived=None, exportable=None,
                           key_type=None, mount_point='transit'):
        """
        POST /<mount_point>/keys/<name>
        """
        url = '/v1/{0}/keys/{1}'.format(mount_point, name)
        params = {}
        if convergent_encryption is not None:
            params['convergent_encryption'] = convergent_encryption
        if derived is not None:
            params['derived'] = derived
        if exportable is not None:
            params['exportable'] = exportable
        if key_type is not None:
            params['type'] = key_type

        return self._post(url, json=params)

    def transit_read_key(self, name, mount_point='transit'):
        """
        GET /<mount_point>/keys/<name>
        """
        url = '/v1/{0}/keys/{1}'.format(mount_point, name)
        return self._get(url).json()

    def transit_list_keys(self, mount_point='transit'):
        """
        GET /<mount_point>/keys?list=true
        """
        url = '/v1/{0}/keys?list=true'.format(mount_point)
        return self._get(url).json()

    def transit_delete_key(self, name, mount_point='transit'):
        """
        DELETE /<mount_point>/keys/<name>
        """
        url = '/v1/{0}/keys/{1}'.format(mount_point, name)
        return self._delete(url)

    def transit_update_key(self, name, min_decryption_version=None, min_encryption_version=None, deletion_allowed=None,
                           mount_point='transit'):
        """
        POST /<mount_point>/keys/<name>/config
        """
        url = '/v1/{0}/keys/{1}/config'.format(mount_point, name)
        params = {}
        if min_decryption_version is not None:
            params['min_decryption_version'] = min_decryption_version
        if min_encryption_version is not None:
            params['min_encryption_version'] = min_encryption_version
        if deletion_allowed is not None:
            params['deletion_allowed'] = deletion_allowed

        return self._post(url, json=params)

    def transit_rotate_key(self, name, mount_point='transit'):
        """
        POST /<mount_point>/keys/<name>/rotate
        """
        url = '/v1/{0}/keys/{1}/rotate'.format(mount_point, name)
        return self._post(url)

    def transit_export_key(self, name, key_type, version=None, mount_point='transit'):
        """
        GET /<mount_point>/export/<key_type>/<name>(/<version>)
        """
        if version is not None:
            url = '/v1/{0}/export/{1}/{2}/{3}'.format(mount_point, key_type, name, version)
        else:
            url = '/v1/{0}/export/{1}/{2}'.format(mount_point, key_type, name)
        return self._get(url).json()

    def transit_encrypt_data(self, name, plaintext, context=None, key_version=None, nonce=None, batch_input=None,
                             key_type=None, convergent_encryption=None, mount_point='transit'):
        """
        POST /<mount_point>/encrypt/<name>
        """
        url = '/v1/{0}/encrypt/{1}'.format(mount_point, name)
        params = {
            'plaintext': plaintext
        }
        if context is not None:
            params['context'] = context
        if key_version is not None:
            params['key_version'] = key_version
        if nonce is not None:
            params['nonce'] = nonce
        if batch_input is not None:
            params['batch_input'] = batch_input
        if key_type is not None:
            params['type'] = key_type
        if convergent_encryption is not None:
            params['convergent_encryption'] = convergent_encryption

        return self._post(url, json=params).json()

    def transit_decrypt_data(self, name, ciphertext, context=None, nonce=None, batch_input=None, mount_point='transit'):
        """
        POST /<mount_point>/decrypt/<name>
        """
        url = '/v1/{0}/decrypt/{1}'.format(mount_point, name)
        params = {
            'ciphertext': ciphertext
        }
        if context is not None:
            params['context'] = context
        if nonce is not None:
            params['nonce'] = nonce
        if batch_input is not None:
            params['batch_input'] = batch_input

        return self._post(url, json=params).json()

    def transit_rewrap_data(self, name, ciphertext, context=None, key_version=None, nonce=None, batch_input=None,
                            mount_point='transit'):
        """
        POST /<mount_point>/rewrap/<name>
        """
        url = '/v1/{0}/rewrap/{1}'.format(mount_point, name)
        params = {
            'ciphertext': ciphertext
        }
        if context is not None:
            params['context'] = context
        if key_version is not None:
            params['key_version'] = key_version
        if nonce is not None:
            params['nonce'] = nonce
        if batch_input is not None:
            params['batch_input'] = batch_input

        return self._post(url, json=params).json()

    def transit_generate_data_key(self, name, key_type, context=None, nonce=None, bits=None, mount_point='transit'):
        """
        POST /<mount_point>/datakey/<type>/<name>
        """
        url = '/v1/{0}/datakey/{1}/{2}'.format(mount_point, key_type, name)
        params = {}
        if context is not None:
            params['context'] = context
        if nonce is not None:
            params['nonce'] = nonce
        if bits is not None:
            params['bits'] = bits

        return self._post(url, json=params).json()

    def transit_generate_rand_bytes(self, data_bytes=None, output_format=None, mount_point='transit'):
        """
        POST /<mount_point>/random(/<data_bytes>)
        """
        if data_bytes is not None:
            url = '/v1/{0}/random/{1}'.format(mount_point, data_bytes)
        else:
            url = '/v1/{0}/random'.format(mount_point)

        params = {}
        if output_format is not None:
            params["format"] = output_format

        return self._post(url, json=params).json()

    def transit_hash_data(self, hash_input, algorithm=None, output_format=None, mount_point='transit'):
        """
        POST /<mount_point>/hash(/<algorithm>)
        """
        if algorithm is not None:
            url = '/v1/{0}/hash/{1}'.format(mount_point, algorithm)
        else:
            url = '/v1/{0}/hash'.format(mount_point)

        params = {
            'input': hash_input
        }
        if output_format is not None:
            params['format'] = output_format

        return self._post(url, json=params).json()

    def transit_generate_hmac(self, name, hmac_input, key_version=None, algorithm=None, mount_point='transit'):
        """
        POST /<mount_point>/hmac/<name>(/<algorithm>)
        """
        if algorithm is not None:
            url = '/v1/{0}/hmac/{1}/{2}'.format(mount_point, name, algorithm)
        else:
            url = '/v1/{0}/hmac/{1}'.format(mount_point, name)
        params = {
            'input': hmac_input
        }
        if key_version is not None:
            params['key_version'] = key_version

        return self._post(url, json=params).json()

    def transit_sign_data(self, name, input_data, key_version=None, algorithm=None, context=None, prehashed=None,
                          mount_point='transit'):
        """
        POST /<mount_point>/sign/<name>(/<algorithm>)
        """
        if algorithm is not None:
            url = '/v1/{0}/sign/{1}/{2}'.format(mount_point, name, algorithm)
        else:
            url = '/v1/{0}/sign/{1}'.format(mount_point, name)

        params = {
            'input': input_data
        }
        if key_version is not None:
            params['key_version'] = key_version
        if context is not None:
            params['context'] = context
        if prehashed is not None:
            params['prehashed'] = prehashed

        return self._post(url, json=params).json()

    def transit_verify_signed_data(self, name, input_data, algorithm=None, signature=None, hmac=None, context=None,
                                   prehashed=None, mount_point='transit'):
        """
        POST /<mount_point>/verify/<name>(/<algorithm>)
        """
        if algorithm is not None:
            url = '/v1/{0}/verify/{1}/{2}'.format(mount_point, name, algorithm)
        else:
            url = '/v1/{0}/verify/{1}'.format(mount_point, name)

        params = {
            'input': input_data
        }
        if signature is not None:
            params['signature'] = signature
        if hmac is not None:
            params['hmac'] = hmac
        if context is not None:
            params['context'] = context
        if prehashed is not None:
            params['prehashed'] = prehashed

        return self._post(url, json=params).json()

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
        elif status_code == 501:
            raise exceptions.VaultNotInitialized(message, errors=errors)
        elif status_code == 503:
            raise exceptions.VaultDown(message, errors=errors)
        else:
            raise exceptions.UnexpectedError(message)

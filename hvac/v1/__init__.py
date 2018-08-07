from __future__ import unicode_literals

import json
from base64 import b64encode

try:
    import hcl

    has_hcl_parser = True
except ImportError:
    has_hcl_parser = False

from hvac import aws_utils, exceptions, adapters, utils, api


class Client(object):
    """The hvac Client class for HashiCorp's Vault."""

    def __init__(self, url='http://localhost:8200', token=None,
                 cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None, adapter=None):
        """Creates a new hvac client instnace.

        :param url: Base URL for the Vault instance being addressed.
        :type url: str
        :param token: Authentication token to include in requests sent to Vault.
        :type token: str
        :param cert: Certificates for use in requests sent to the Vault instance. This should be a tuple with the
            certificate and then key.
        :type cert: tuple
        :param verify: Either a boolean to indicate whether TLS verification should be performed when sending requests to Vault,
            or a string pointing at the CA bundle to use for verification. See http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification.
        :type verify: Union[bool,str]
        :param timeout: The timeout value for requests sent to Vault.
        :type timeout: int
        :param proxies: Proxies to use when preforming requests.
            See: http://docs.python-requests.org/en/master/user/advanced/#proxies
        :type proxies: dict
        :param allow_redirects: Whether to follow redirects when sending requests to Vault.
        :type allow_redirects: bool
        :param session: Optional session object to use when performing request.
        :type session: request.Session
        :param adapter: Optional class to be used for performing requests. If none is provided, defaults to
            hvac.adapters.Request
        :type adapter: hvac.adapters.Adapter
        """

        if adapter is not None:
            self._adapter = adapter
        else:
            self._adapter = adapters.Request(
                base_uri=url,
                token=token,
                cert=cert,
                verify=verify,
                timeout=timeout,
                proxies=proxies,
                allow_redirects=allow_redirects,
                session=session,
            )

        # Instantiate API classes to be exposed as properties on this class
        self._github = api.auth.Github(adapter=self._adapter)
        self._ldap = api.auth.Ldap(adapter=self._adapter)
        self._mfa = api.auth.Mfa(adapter=self._adapter)

    @property
    def adapter(self):
        return self._adapter

    @adapter.setter
    def adapter(self, adapter):
        self._adapter = adapter

    @property
    def url(self):
        return self._adapter.base_uri

    @url.setter
    def url(self, url):
        self._adapter.base_uri = url

    @property
    def token(self):
        return self._adapter.token

    @token.setter
    def token(self, token):
        self._adapter.token = token

    @property
    def session(self):
        return self._adapter.session

    @session.setter
    def session(self, session):
        self._adapter.session = session

    @property
    def allow_redirects(self):
        return self._adapter.allow_redirects

    @allow_redirects.setter
    def allow_redirects(self, allow_redirects):
        self._adapter.allow_redirects = allow_redirects

    @property
    def github(self):
        """Accessor for the Client instance's Github methods. Provided via the :py:class:`hvac.api.auth.Github` class.

        :return: This Client instance's associated Github instance.
        :rtype: hvac.api.auth.Github
        """
        return self._github

    @property
    def ldap(self):
        """Accessor for the Client instance's LDAP methods. Provided via the :py:class:`hvac.api.auth.Ldap` class.

        :return: This Client instance's associated Ldap instance.
        :rtype: hvac.api.auth.Ldap
        """
        return self._ldap

    @property
    def mfa(self):
        """Accessor for the Client instance's MFA methods. Provided via the :py:class:`hvac.api.auth.mfa` class.

        :return: This Client instance's associated MFA instance.
        :rtype: hvac.api.auth.mfa
        """
        return self._mfa

    def read(self, path, wrap_ttl=None):
        """GET /<path>

        :param path:
        :type path:
        :param wrap_ttl:
        :type wrap_ttl:
        :return:
        :rtype:
        """
        try:
            return self._adapter.get('/v1/{0}'.format(path), wrap_ttl=wrap_ttl).json()
        except exceptions.InvalidPath:
            return None

    def list(self, path):
        """GET /<path>?list=true

        :param path:
        :type path:
        :return:
        :rtype:
        """
        try:
            payload = {
                'list': True
            }
            return self._adapter.get('/v1/{}'.format(path), params=payload).json()
        except exceptions.InvalidPath:
            return None

    def write(self, path, wrap_ttl=None, **kwargs):
        """POST /<path>

        :param path:
        :type path:
        :param wrap_ttl:
        :type wrap_ttl:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """
        response = self._adapter.post('/v1/{0}'.format(path), json=kwargs, wrap_ttl=wrap_ttl)

        if response.status_code == 200:
            return response.json()

    def delete(self, path):
        """DELETE /<path>

        :param path:
        :type path:
        :return:
        :rtype:
        """
        self._adapter.delete('/v1/{0}'.format(path))

    def unwrap(self, token=None):
        """POST /sys/wrapping/unwrap

        :param token:
        :type token:
        :return:
        :rtype:
        """
        if token:
            payload = {
                'token': token
            }
            return self._adapter.post('/v1/sys/wrapping/unwrap', json=payload).json()
        else:
            return self._adapter.post('/v1/sys/wrapping/unwrap').json()

    def is_initialized(self):
        """GET /sys/init

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/init').json()['initialized']

    def initialize(self, secret_shares=5, secret_threshold=3, pgp_keys=None):
        """PUT /sys/init

        :param secret_shares:
        :type secret_shares:
        :param secret_threshold:
        :type secret_threshold:
        :param pgp_keys:
        :type pgp_keys:
        :return:
        :rtype:
        """
        params = {
            'secret_shares': secret_shares,
            'secret_threshold': secret_threshold,
        }

        if pgp_keys:
            if len(pgp_keys) != secret_shares:
                raise ValueError('Length of pgp_keys must equal secret shares')

            params['pgp_keys'] = pgp_keys

        return self._adapter.put('/v1/sys/init', json=params).json()

    @property
    def seal_status(self):
        """GET /sys/seal-status

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/seal-status').json()

    def is_sealed(self):
        """

        :return:
        :rtype:
        """
        return self.seal_status['sealed']

    def seal(self):
        """PUT /sys/seal

        :return:
        :rtype:
        """
        self._adapter.put('/v1/sys/seal')

    def unseal_reset(self):
        """PUT /sys/unseal

        :return:
        :rtype:
        """
        params = {
            'reset': True,
        }
        return self._adapter.put('/v1/sys/unseal', json=params).json()

    def unseal(self, key):
        """PUT /sys/unseal

        :param key:
        :type key:
        :return:
        :rtype:
        """
        params = {
            'key': key,
        }

        return self._adapter.put('/v1/sys/unseal', json=params).json()

    def unseal_multi(self, keys):
        """

        :param keys:
        :type keys:
        :return:
        :rtype:
        """
        result = None

        for key in keys:
            result = self.unseal(key)
            if not result['sealed']:
                break

        return result

    @property
    def generate_root_status(self):
        """GET /sys/generate-root/attempt

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/generate-root/attempt').json()

    def start_generate_root(self, key, otp=False):
        """PUT /sys/generate-root/attempt

        :param key:
        :type key:
        :param otp:
        :type otp:
        :return:
        :rtype:
        """
        params = {}
        if otp:
            params['otp'] = key
        else:
            params['pgp_key'] = key

        return self._adapter.put('/v1/sys/generate-root/attempt', json=params).json()

    def generate_root(self, key, nonce):
        """PUT /sys/generate-root/update

        :param key:
        :type key:
        :param nonce:
        :type nonce:
        :return:
        :rtype:
        """
        params = {
            'key': key,
            'nonce': nonce,
        }

        return self._adapter.put('/v1/sys/generate-root/update', json=params).json()

    def cancel_generate_root(self):
        """DELETE /sys/generate-root/attempt

        :return:
        :rtype:
        """

        return self._adapter.delete('/v1/sys/generate-root/attempt').status_code == 204

    @property
    def key_status(self):
        """GET /sys/key-status

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/key-status').json()

    def rotate(self):
        """PUT /sys/rotate

        :return:
        :rtype:
        """
        self._adapter.put('/v1/sys/rotate')

    @property
    def rekey_status(self):
        """GET /sys/rekey/init

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/rekey/init').json()

    def start_rekey(self, secret_shares=5, secret_threshold=3, pgp_keys=None,
                    backup=False):
        """PUT /sys/rekey/init

        :param secret_shares:
        :type secret_shares:
        :param secret_threshold:
        :type secret_threshold:
        :param pgp_keys:
        :type pgp_keys:
        :param backup:
        :type backup:
        :return:
        :rtype:
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

        resp = self._adapter.put('/v1/sys/rekey/init', json=params)
        if resp.text:
            return resp.json()

    def cancel_rekey(self):
        """DELETE /sys/rekey/init

        :return:
        :rtype:
        """
        self._adapter.delete('/v1/sys/rekey/init')

    def rekey(self, key, nonce=None):
        """PUT /sys/rekey/update

        :param key:
        :type key:
        :param nonce:
        :type nonce:
        :return:
        :rtype:
        """
        params = {
            'key': key,
        }

        if nonce:
            params['nonce'] = nonce

        return self._adapter.put('/v1/sys/rekey/update', json=params).json()

    def rekey_multi(self, keys, nonce=None):
        """

        :param keys:
        :type keys:
        :param nonce:
        :type nonce:
        :return:
        :rtype:
        """
        result = None

        for key in keys:
            result = self.rekey(key, nonce=nonce)
            if result.get('complete'):
                break

        return result

    def get_backed_up_keys(self):
        """GET /sys/rekey/backup

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/rekey/backup').json()

    @property
    def ha_status(self):
        """GET /sys/leader

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/leader').json()

    def read_lease(self, lease_id):
        """PUT /sys/leases/lookup

        :param lease_id: Specifies the ID of the lease to lookup.
        :type lease_id: str.
        :return: Parsed JSON response from the leases PUT request
        :rtype: dict.
        """
        params = {
            'lease_id': lease_id
        }
        return self._adapter.put('/v1/sys/leases/lookup', json=params).json()

    def renew_secret(self, lease_id, increment=None):
        """PUT /sys/leases/renew

        :param lease_id:
        :type lease_id:
        :param increment:
        :type increment:
        :return:
        :rtype:
        """
        params = {
            'lease_id': lease_id,
            'increment': increment,
        }
        return self._adapter.put('/v1/sys/leases/renew', json=params).json()

    def revoke_secret(self, lease_id):
        """PUT /sys/revoke/<lease id>

        :param lease_id:
        :type lease_id:
        :return:
        :rtype:
        """
        self._adapter.put('/v1/sys/revoke/{0}'.format(lease_id))

    def revoke_secret_prefix(self, path_prefix):
        """PUT /sys/revoke-prefix/<path prefix>

        :param path_prefix:
        :type path_prefix:
        :return:
        :rtype:
        """
        self._adapter.put('/v1/sys/revoke-prefix/{0}'.format(path_prefix))

    def revoke_self_token(self):
        """PUT /auth/token/revoke-self

        :return:
        :rtype:
        """
        self._adapter.put('/v1/auth/token/revoke-self')

    def list_secret_backends(self):
        """GET /sys/mounts

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/mounts').json()

    def enable_secret_backend(self, backend_type, description=None, mount_point=None, config=None, options=None):
        """POST /sys/auth/<mount point>

        :param backend_type:
        :type backend_type:
        :param description:
        :type description:
        :param mount_point:
        :type mount_point:
        :param config:
        :type config:
        :param options:
        :type options:
        :return:
        :rtype:
        """
        if not mount_point:
            mount_point = backend_type

        params = {
            'type': backend_type,
            'description': description,
            'config': config,
            'options': options,
        }

        self._adapter.post('/v1/sys/mounts/{0}'.format(mount_point), json=params)

    def tune_secret_backend(self, backend_type, mount_point=None, default_lease_ttl=None, max_lease_ttl=None, description=None,
                            audit_non_hmac_request_keys=None, audit_non_hmac_response_keys=None, listing_visibility=None,
                            passthrough_request_headers=None):
        """POST /sys/mounts/<mount point>/tune

        :param backend_type: Type of the secret backend to modify
        :type backend_type: str
        :param mount_point: The path the associated secret backend is mounted
        :type mount_point: str
        :param description: Specifies the description of the mount. This overrides the current stored value, if any.
        :type description: str
        :param default_lease_ttl: Default time-to-live. This overrides the global default. A value of 0 is equivalent to
            the system default TTL
        :type default_lease_ttl: int
        :param max_lease_ttl: Maximum time-to-live. This overrides the global default. A value of 0 are equivalent and
            set to the system max TTL.
        :type max_lease_ttl: int
        :param audit_non_hmac_request_keys: Specifies the comma-separated list of keys that will not be HMAC'd by audit
            devices in the request data object.
        :type audit_non_hmac_request_keys: list
        :param audit_non_hmac_response_keys: Specifies the comma-separated list of keys that will not be HMAC'd by audit
            devices in the response data object.
        :type audit_non_hmac_response_keys: list
        :param listing_visibility: Speficies whether to show this mount in the UI-specific listing endpoint. Valid
            values are "unauth" or "".
        :type listing_visibility: str
        :param passthrough_request_headers: Comma-separated list of headers to whitelist and pass from the request
            to the backend.
        :type passthrough_request_headers: str

        :return: The JSON response from Vault
        :rtype: dict.
        """

        if not mount_point:
            mount_point = backend_type
        # All parameters are optional for this method. Until/unless we include input validation, we simply loop over the
        # parameters and add which parameters are set.
        optional_parameters = [
            'default_lease_ttl',
            'max_lease_ttl',
            'description',
            'audit_non_hmac_request_keys',
            'audit_non_hmac_response_keys',
            'listing_visibility',
            'passthrough_request_headers',
        ]
        params = {}
        for optional_parameter in optional_parameters:
            if locals().get(optional_parameter) is not None:
                params[optional_parameter] = locals().get(optional_parameter)
        return self._adapter.post('/v1/sys/mounts/{0}/tune'.format(mount_point), json=params)

    def get_secret_backend_tuning(self, backend_type, mount_point=None):
        """GET /sys/mounts/<mount point>/tune

        :param backend_type:
        :type backend_type:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        if not mount_point:
            mount_point = backend_type

        return self._adapter.get('/v1/sys/mounts/{0}/tune'.format(mount_point)).json()

    def disable_secret_backend(self, mount_point):
        """DELETE /sys/mounts/<mount point>

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        self._adapter.delete('/v1/sys/mounts/{0}'.format(mount_point))

    def remount_secret_backend(self, from_mount_point, to_mount_point):
        """POST /sys/remount

        :param from_mount_point:
        :type from_mount_point:
        :param to_mount_point:
        :type to_mount_point:
        :return:
        :rtype:
        """
        params = {
            'from': from_mount_point,
            'to': to_mount_point,
        }

        self._adapter.post('/v1/sys/remount', json=params)

    def list_policies(self):
        """GET /sys/policy

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/policy').json()['policies']

    def get_policy(self, name, parse=False):
        """GET /sys/policy/<name>

        :param name:
        :type name:
        :param parse:
        :type parse:
        :return:
        :rtype:
        """
        try:
            policy = self._adapter.get('/v1/sys/policy/{0}'.format(name)).json()['rules']
            if parse:
                if not has_hcl_parser:
                    raise ImportError('pyhcl is required for policy parsing')

                policy = hcl.loads(policy)

            return policy
        except exceptions.InvalidPath:
            return None

    def set_policy(self, name, rules):
        """PUT /sys/policy/<name>

        :param name:
        :type name:
        :param rules:
        :type rules:
        :return:
        :rtype:
        """

        if isinstance(rules, dict):
            rules = json.dumps(rules)

        params = {
            'rules': rules,
        }

        self._adapter.put('/v1/sys/policy/{0}'.format(name), json=params)

    def delete_policy(self, name):
        """DELETE /sys/policy/<name>

        :param name:
        :type name:
        :return:
        :rtype:
        """
        self._adapter.delete('/v1/sys/policy/{0}'.format(name))

    def list_audit_backends(self):
        """GET /sys/audit

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/audit').json()

    def enable_audit_backend(self, backend_type, description=None, options=None, name=None):
        """POST /sys/audit/<name>

        :param backend_type:
        :type backend_type:
        :param description:
        :type description:
        :param options:
        :type options:
        :param name:
        :type name:
        :return:
        :rtype:
        """
        if not name:
            name = backend_type

        params = {
            'type': backend_type,
            'description': description,
            'options': options,
        }

        self._adapter.post('/v1/sys/audit/{0}'.format(name), json=params)

    def disable_audit_backend(self, name):
        """DELETE /sys/audit/<name>

        :param name:
        :type name:
        :return:
        :rtype:
        """
        self._adapter.delete('/v1/sys/audit/{0}'.format(name))

    def audit_hash(self, name, input):
        """POST /sys/audit-hash

        :param name:
        :type name:
        :param input:
        :type input:
        :return:
        :rtype:
        """
        params = {
            'input': input,
        }
        return self._adapter.post('/v1/sys/audit-hash/{0}'.format(name), json=params).json()

    def create_token(self, role=None, token_id=None, policies=None, meta=None,
                     no_parent=False, lease=None, display_name=None,
                     num_uses=None, no_default_policy=False,
                     ttl=None, orphan=False, wrap_ttl=None, renewable=None,
                     explicit_max_ttl=None, period=None):
        """POST /auth/token/create

        POST /auth/token/create/<role>

        POST /auth/token/create-orphan

        :param role:
        :type role:
        :param token_id:
        :type token_id:
        :param policies:
        :type policies:
        :param meta:
        :type meta:
        :param no_parent:
        :type no_parent:
        :param lease:
        :type lease:
        :param display_name:
        :type display_name:
        :param num_uses:
        :type num_uses:
        :param no_default_policy:
        :type no_default_policy:
        :param ttl:
        :type ttl:
        :param orphan:
        :type orphan:
        :param wrap_ttl:
        :type wrap_ttl:
        :param renewable:
        :type renewable:
        :param explicit_max_ttl:
        :type explicit_max_ttl:
        :param period:
        :type period:
        :return:
        :rtype:
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
            return self._adapter.post('/v1/auth/token/create-orphan', json=params, wrap_ttl=wrap_ttl).json()
        elif role:
            return self._adapter.post('/v1/auth/token/create/{0}'.format(role), json=params, wrap_ttl=wrap_ttl).json()
        else:
            return self._adapter.post('/v1/auth/token/create', json=params, wrap_ttl=wrap_ttl).json()

    def lookup_token(self, token=None, accessor=False, wrap_ttl=None):
        """GET /auth/token/lookup/<token>

        GET /auth/token/lookup-accessor/<token-accessor>

        GET /auth/token/lookup-self

        :param token:
        :type token: str.
        :param accessor:
        :type accessor: str.
        :param wrap_ttl:
        :type wrap_ttl: int.
        :return:
        :rtype:
        """
        token_param = {
            'token': token,
        }
        accessor_param = {
            'accessor': token,
        }
        if token:
            if accessor:
                path = '/v1/auth/token/lookup-accessor'
                return self._adapter.post(path, json=accessor_param, wrap_ttl=wrap_ttl).json()
            else:
                path = '/v1/auth/token/lookup'
                return self._adapter.post(path, json=token_param).json()
        else:
            path = '/v1/auth/token/lookup-self'
            return self._adapter.get(path, wrap_ttl=wrap_ttl).json()

    def revoke_token(self, token, orphan=False, accessor=False):
        """POST /auth/token/revoke

        POST /auth/token/revoke-orphan

        POST /auth/token/revoke-accessor

        :param token:
        :type token:
        :param orphan:
        :type orphan:
        :param accessor:
        :type accessor:
        :return:
        :rtype:
        """
        if accessor and orphan:
            msg = "revoke_token does not support 'orphan' and 'accessor' flags together"
            raise exceptions.InvalidRequest(msg)
        elif accessor:
            params = {'accessor': token}
            self._adapter.post('/v1/auth/token/revoke-accessor', json=params)
        elif orphan:
            params = {'token': token}
            self._adapter.post('/v1/auth/token/revoke-orphan', json=params)
        else:
            params = {'token': token}
            self._adapter.post('/v1/auth/token/revoke', json=params)

    def revoke_token_prefix(self, prefix):
        """POST /auth/token/revoke-prefix/<prefix>

        :param prefix:
        :type prefix:
        :return:
        :rtype:
        """
        self._adapter.post('/v1/auth/token/revoke-prefix/{0}'.format(prefix))

    def renew_token(self, token=None, increment=None, wrap_ttl=None):
        """POST /auth/token/renew/<token>

        POST /auth/token/renew-self

        :param token:
        :type token:
        :param increment:
        :type increment:
        :param wrap_ttl:
        :type wrap_ttl:
        :return:
        :rtype:
        """
        params = {
            'increment': increment,
        }

        if token:
            path = '/v1/auth/token/renew/{0}'.format(token)
            return self._adapter.post(path, json=params, wrap_ttl=wrap_ttl).json()
        else:
            return self._adapter.post('/v1/auth/token/renew-self', json=params, wrap_ttl=wrap_ttl).json()

    def create_token_role(self, role,
                          allowed_policies=None, disallowed_policies=None,
                          orphan=None, period=None, renewable=None,
                          path_suffix=None, explicit_max_ttl=None):
        """POST /auth/token/roles/<role>

        :param role:
        :type role:
        :param allowed_policies:
        :type allowed_policies:
        :param disallowed_policies:
        :type disallowed_policies:
        :param orphan:
        :type orphan:
        :param period:
        :type period:
        :param renewable:
        :type renewable:
        :param path_suffix:
        :type path_suffix:
        :param explicit_max_ttl:
        :type explicit_max_ttl:
        :return:
        :rtype:
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
        return self._adapter.post('/v1/auth/token/roles/{0}'.format(role), json=params)

    def token_role(self, role):
        """Returns the named token role.

        :param role:
        :type role:
        :return:
        :rtype:
        """
        return self.read('auth/token/roles/{0}'.format(role))

    def delete_token_role(self, role):
        """Deletes the named token role.

        :param role:
        :type role:
        :return:
        :rtype:
        """
        return self.delete('auth/token/roles/{0}'.format(role))

    def list_token_roles(self):
        """GET /auth/token/roles?list=true

        :return:
        :rtype:
        """
        return self.list('auth/token/roles')

    def logout(self, revoke_token=False):
        """Clears the token used for authentication, optionally revoking it before doing so.

        :param revoke_token:
        :type revoke_token:
        :return:
        :rtype:
        """
        if revoke_token:
            self.revoke_self_token()

        self.token = None

    def is_authenticated(self):
        """Helper method which returns the authentication status of the client

        :return:
        :rtype:
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
        """POST /auth/<mount point>/login

        :param app_id:
        :type app_id:
        :param user_id:
        :type user_id:
        :param mount_point:
        :type mount_point:
        :param use_token:
        :type use_token:
        :return:
        :rtype:
        """
        params = {
            'app_id': app_id,
            'user_id': user_id,
        }

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def auth_tls(self, mount_point='cert', use_token=True):
        """POST /auth/<mount point>/login

        :param mount_point:
        :type mount_point:
        :param use_token:
        :type use_token:
        :return:
        :rtype:
        """
        return self.auth('/v1/auth/{0}/login'.format(mount_point), use_token=use_token)

    def auth_userpass(self, username, password, mount_point='userpass', use_token=True, **kwargs):
        """POST /auth/<mount point>/login/<username>

        :param username:
        :type username:
        :param password:
        :type password:
        :param mount_point:
        :type mount_point:
        :param use_token:
        :type use_token:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """
        params = {
            'password': password,
        }

        params.update(kwargs)

        return self.auth('/v1/auth/{0}/login/{1}'.format(mount_point, username), json=params, use_token=use_token)

    def auth_aws_iam(self, access_key, secret_key, session_token=None, header_value=None, mount_point='aws', role='', use_token=True, region='us-east-1'):
        """POST /auth/<mount point>/login

        :param access_key: AWS IAM access key ID
        :type access_key: str
        :param secret_key: AWS IAM secret access key
        :type secret_key: str
        :param session_token: Optional AWS IAM session token retrieved via a GetSessionToken AWS API request.
            see: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html
        :type session_token: str
        :param header_value: Vault allows you to require an additional header, X-Vault-AWS-IAM-Server-ID, to be present
            to mitigate against different types of replay attacks. Depending on the configuration of the AWS auth
            backend, providing a argument to this optional parameter may be required.
        :type header_value: str
        :param mount_point: The "path" the AWS auth backend was mounted on. Vault currently defaults to "aws". "aws-ec2"
            is the default argument for backwards comparability within this module.
        :type mount_point: str
        :param role: Name of the role against which the login is being attempted. If role is not specified, then the
            login endpoint looks for a role bearing the name of the AMI ID of the EC2 instance that is trying to login
            if using the ec2 auth method, or the "friendly name" (i.e., role name or username) of the IAM principal
            authenticated. If a matching role is not found, login fails.
        :type role: str
        :param use_token: If True, uses the token in the response received from the auth request to set the "token"
            attribute on the current Client class instance.
        :type use_token: bool.
        :return: The response from the AWS IAM login request attempt.
        :rtype: requests.Response
        """
        request = aws_utils.generate_sigv4_auth_request(header_value=header_value)

        auth = aws_utils.SigV4Auth(access_key, secret_key, session_token, region)
        auth.add_auth(request)

        # https://github.com/hashicorp/vault/blob/master/builtin/credential/aws/cli.go
        headers = json.dumps({k: [request.headers[k]] for k in request.headers})
        params = {
            'iam_http_request_method': request.method,
            'iam_request_url': b64encode(request.url.encode('utf-8')).decode('utf-8'),
            'iam_request_headers': b64encode(headers.encode('utf-8')).decode('utf-8'),
            'iam_request_body': b64encode(request.body.encode('utf-8')).decode('utf-8'),
            'role': role,
        }

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def auth_ec2(self, pkcs7, nonce=None, role=None, use_token=True, mount_point='aws-ec2'):
        """POST /auth/<mount point>/login

        :param pkcs7: PKCS#7 version of an AWS Instance Identity Document from the EC2 Metadata Service.
        :type pkcs7: str.
        :param nonce: Optional nonce returned as part of the original authentication request. Not required if the backend
            has "allow_instance_migration" or "disallow_reauthentication" options turned on.
        :type nonce: str.
        :param role: Identifier for the AWS auth backend role being requested.
        :type role: str.
        :param use_token: If True, uses the token in the response received from the auth request to set the "token"
            attribute on the current Client class instance.
        :type use_token: bool.
        :param mount_point: The "path" the AWS auth backend was mounted on. Vault currently defaults to "aws". "aws-ec2"
            is the default argument for backwards comparability within this module.
        :type mount_point: str.
        :return: parsed JSON response from the auth POST request
        :rtype: dict.

        """
        params = {'pkcs7': pkcs7}
        if nonce:
            params['nonce'] = nonce
        if role:
            params['role'] = role

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def auth_gcp(self, role, jwt, mount_point='gcp', use_token=True):
        """
        POST /auth/<mount point>/login

        :param role: identifier for the GCP auth backend role being requested
        :type role: str.
        :param jwt: JSON Web Token from the GCP metadata service
        :type jwt: str.
        :param mount_point: The "path" the GCP auth backend was mounted on. Vault currently defaults to "gcp".
        :type mount_point: str.
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the current Client class instance.
        :type use_token: bool.
        :return: parsed JSON response from the auth POST request
        :rtype: dict.
        """

        params = {
            'role': role,
            'jwt': jwt
        }

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def create_userpass(self, username, password, policies, mount_point='userpass', **kwargs):
        """POST /auth/<mount point>/users/<username>

        :param username:
        :type username:
        :param password:
        :type password:
        :param policies:
        :type policies:
        :param mount_point:
        :type mount_point:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
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

        return self._adapter.post('/v1/auth/{}/users/{}'.format(mount_point, username), json=params)

    def list_userpass(self, mount_point='userpass'):
        """GET /auth/<mount point>/users?list=true

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        try:
            return self._adapter.get('/v1/auth/{}/users'.format(mount_point), params={'list': True}).json()
        except exceptions.InvalidPath:
            return None

    def read_userpass(self, username, mount_point='userpass'):
        """GET /auth/<mount point>/users/<username>

        :param username:
        :type username:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.get('/v1/auth/{}/users/{}'.format(mount_point, username)).json()

    def update_userpass_policies(self, username, policies, mount_point='userpass'):
        """POST /auth/<mount point>/users/<username>/policies

        :param username:
        :type username:
        :param policies:
        :type policies:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        # userpass can have more than 1 policy. It is easier for the user to pass in the
        # policies as a list so if they do, we need to convert to a , delimited string.
        if isinstance(policies, (list, set, tuple)):
            policies = ','.join(policies)

        params = {
            'policies': policies
        }

        return self._adapter.post('/v1/auth/{}/users/{}/policies'.format(mount_point, username), json=params)

    def update_userpass_password(self, username, password, mount_point='userpass'):
        """POST /auth/<mount point>/users/<username>/password

        :param username:
        :type username:
        :param password:
        :type password:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        params = {
            'password': password
        }
        return self._adapter.post('/v1/auth/{}/users/{}/password'.format(mount_point, username), json=params)

    def delete_userpass(self, username, mount_point='userpass'):
        """DELETE /auth/<mount point>/users/<username>

        :param username:
        :type username:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.delete('/v1/auth/{}/users/{}'.format(mount_point, username))

    def create_app_id(self, app_id, policies, display_name=None, mount_point='app-id', **kwargs):
        """POST /auth/<mount point>/map/app-id/<app_id>

        :param app_id:
        :type app_id:
        :param policies:
        :type policies:
        :param display_name:
        :type display_name:
        :param mount_point:
        :type mount_point:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
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

        return self._adapter.post('/v1/auth/{}/map/app-id/{}'.format(mount_point, app_id), json=params)

    def get_app_id(self, app_id, mount_point='app-id', wrap_ttl=None):
        """GET /auth/<mount_point>/map/app-id/<app_id>

        :param app_id:
        :type app_id:
        :param mount_point:
        :type mount_point:
        :param wrap_ttl:
        :type wrap_ttl:
        :return:
        :rtype:
        """
        path = '/v1/auth/{0}/map/app-id/{1}'.format(mount_point, app_id)
        return self._adapter.get(path, wrap_ttl=wrap_ttl).json()

    def delete_app_id(self, app_id, mount_point='app-id'):
        """DELETE /auth/<mount_point>/map/app-id/<app_id>

        :param app_id:
        :type app_id:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.delete('/v1/auth/{0}/map/app-id/{1}'.format(mount_point, app_id))

    def create_user_id(self, user_id, app_id, cidr_block=None, mount_point='app-id', **kwargs):
        """POST /auth/<mount point>/map/user-id/<user_id>

        :param user_id:
        :type user_id:
        :param app_id:
        :type app_id:
        :param cidr_block:
        :type cidr_block:
        :param mount_point:
        :type mount_point:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
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

        return self._adapter.post('/v1/auth/{}/map/user-id/{}'.format(mount_point, user_id), json=params)

    def get_user_id(self, user_id, mount_point='app-id', wrap_ttl=None):
        """GET /auth/<mount_point>/map/user-id/<user_id>

        :param user_id:
        :type user_id:
        :param mount_point:
        :type mount_point:
        :param wrap_ttl:
        :type wrap_ttl:
        :return:
        :rtype:
        """
        path = '/v1/auth/{0}/map/user-id/{1}'.format(mount_point, user_id)
        return self._adapter.get(path, wrap_ttl=wrap_ttl).json()

    def delete_user_id(self, user_id, mount_point='app-id'):
        """DELETE /auth/<mount_point>/map/user-id/<user_id>

        :param user_id:
        :type user_id:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.delete('/v1/auth/{0}/map/user-id/{1}'.format(mount_point, user_id))

    def create_vault_ec2_client_configuration(self, access_key, secret_key, endpoint=None, mount_point='aws-ec2'):
        """POST /auth/<mount_point>/config/client

        :param access_key:
        :type access_key:
        :param secret_key:
        :type secret_key:
        :param endpoint:
        :type endpoint:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        params = {
            'access_key': access_key,
            'secret_key': secret_key
        }
        if endpoint is not None:
            params['endpoint'] = endpoint

        return self._adapter.post('/v1/auth/{0}/config/client'.format(mount_point), json=params)

    def get_vault_ec2_client_configuration(self, mount_point='aws-ec2'):
        """GET /auth/<mount_point>/config/client

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.get('/v1/auth/{0}/config/client'.format(mount_point)).json()

    def delete_vault_ec2_client_configuration(self, mount_point='aws-ec2'):
        """DELETE /auth/<mount_point>/config/client

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.delete('/v1/auth/{0}/config/client'.format(mount_point))

    def create_vault_ec2_certificate_configuration(self, cert_name, aws_public_cert, mount_point='aws-ec2'):
        """POST /auth/<mount_point>/config/certificate/<cert_name>

        :param cert_name:
        :type cert_name:
        :param aws_public_cert:
        :type aws_public_cert:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        params = {
            'cert_name': cert_name,
            'aws_public_cert': aws_public_cert
        }
        return self._adapter.post('/v1/auth/{0}/config/certificate/{1}'.format(mount_point, cert_name), json=params)

    def get_vault_ec2_certificate_configuration(self, cert_name, mount_point='aws-ec2'):
        """GET /auth/<mount_point>/config/certificate/<cert_name>

        :param cert_name:
        :type cert_name:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.get('/v1/auth/{0}/config/certificate/{1}'.format(mount_point, cert_name)).json()

    def list_vault_ec2_certificate_configurations(self, mount_point='aws-ec2'):
        """GET /auth/<mount_point>/config/certificates?list=true

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        params = {'list': True}
        return self._adapter.get('/v1/auth/{0}/config/certificates'.format(mount_point), params=params).json()

    def create_ec2_role(self, role, bound_ami_id=None, bound_account_id=None, bound_iam_role_arn=None,
                        bound_iam_instance_profile_arn=None, bound_ec2_instance_id=None, bound_region=None,
                        bound_vpc_id=None, bound_subnet_id=None, role_tag=None,  ttl=None, max_ttl=None, period=None,
                        policies=None, allow_instance_migration=False, disallow_reauthentication=False,
                        resolve_aws_unique_ids=None, mount_point='aws-ec2'):
        """POST /auth/<mount_point>/role/<role>

        :param role:
        :type role:
        :param bound_ami_id:
        :type bound_ami_id:
        :param bound_account_id:
        :type bound_account_id:
        :param bound_iam_role_arn:
        :type bound_iam_role_arn:
        :param bound_iam_instance_profile_arn:
        :type bound_iam_instance_profile_arn:
        :param bound_ec2_instance_id:
        :type bound_ec2_instance_id:
        :param bound_region:
        :type bound_region:
        :param bound_vpc_id:
        :type bound_vpc_id:
        :param bound_subnet_id:
        :type bound_subnet_id:
        :param role_tag:
        :type role_tag:
        :param ttl:
        :type ttl:
        :param max_ttl:
        :type max_ttl:
        :param period:
        :type period:
        :param policies:
        :type policies:
        :param allow_instance_migration:
        :type allow_instance_migration:
        :param disallow_reauthentication:
        :type disallow_reauthentication:
        :param resolve_aws_unique_ids:
        :type resolve_aws_unique_ids:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        params = {
            'role': role,
            'auth_type': 'ec2',
            'disallow_reauthentication': disallow_reauthentication,
            'allow_instance_migration': allow_instance_migration
        }

        if bound_ami_id is not None:
            params['bound_ami_id'] = bound_ami_id
        if bound_account_id is not None:
            params['bound_account_id'] = bound_account_id
        if bound_iam_role_arn is not None:
            params['bound_iam_role_arn'] = bound_iam_role_arn
        if bound_ec2_instance_id is not None:
            params['bound_iam_instance_profile_arn'] = bound_ec2_instance_id
        if bound_iam_instance_profile_arn is not None:
            params['bound_iam_instance_profile_arn'] = bound_iam_instance_profile_arn
        if bound_region is not None:
            params['bound_region'] = bound_region
        if bound_vpc_id is not None:
            params['bound_vpc_id'] = bound_vpc_id
        if bound_subnet_id is not None:
            params['bound_subnet_id'] = bound_subnet_id
        if role_tag is not None:
            params['role_tag'] = role_tag
        if ttl is not None:
            params['ttl'] = ttl
        else:
            params['ttl'] = 0
        if max_ttl is not None:
            params['max_ttl'] = max_ttl
        else:
            params['max_ttl'] = 0
        if period is not None:
            params['period'] = period
        else:
            params['period'] = 0
        if policies is not None:
            params['policies'] = policies
        if resolve_aws_unique_ids is not None:
            params['resolve_aws_unique_ids'] = resolve_aws_unique_ids

        return self._adapter.post('/v1/auth/{0}/role/{1}'.format(mount_point, role), json=params)

    def get_ec2_role(self, role, mount_point='aws-ec2'):
        """GET /auth/<mount_point>/role/<role>

        :param role:
        :type role:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.get('/v1/auth/{0}/role/{1}'.format(mount_point, role)).json()

    def delete_ec2_role(self, role, mount_point='aws-ec2'):
        """DELETE /auth/<mount_point>/role/<role>

        :param role:
        :type role:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.delete('/v1/auth/{0}/role/{1}'.format(mount_point, role))

    def list_ec2_roles(self, mount_point='aws-ec2'):
        """GET /auth/<mount_point>/roles?list=true

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        try:
            return self._adapter.get('/v1/auth/{0}/roles'.format(mount_point), params={'list': True}).json()
        except exceptions.InvalidPath:
            return None

    def create_ec2_role_tag(self, role, policies=None, max_ttl=None, instance_id=None,
                            disallow_reauthentication=False, allow_instance_migration=False, mount_point='aws-ec2'):
        """POST /auth/<mount_point>/role/<role>/tag

        :param role:
        :type role:
        :param policies:
        :type policies:
        :param max_ttl:
        :type max_ttl:
        :param instance_id:
        :type instance_id:
        :param disallow_reauthentication:
        :type disallow_reauthentication:
        :param allow_instance_migration:
        :type allow_instance_migration:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
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
        return self._adapter.post('/v1/auth/{0}/role/{1}/tag'.format(mount_point, role), json=params)

    def auth_cubbyhole(self, token):
        """POST /v1/sys/wrapping/unwrap

        :param token:
        :type token:
        :return:
        :rtype:
        """
        self.token = token
        return self.auth('/v1/sys/wrapping/unwrap')

    def auth(self, url, use_token=True, **kwargs):
        """Performs a request (typically to a path prefixed with "/v1/auth") and optionaly stores the client token sent
            in the resulting Vault response for use by the :py:meth:`hvac.adapters.Adapter` instance under the _adapater
            Client attribute.

        :param url: Path to send the authentication request to.
        :type url: str | unicode
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the the :py:meth:`hvac.adapters.Adapter` instance under the _adapater Client attribute.
        :type use_token: bool
        :param kwargs: Additional keyword arguments to include in the params sent with the request.
        :type kwargs: dict
        :return: The response of the auth request.
        :rtype: requests.Response
        """
        return self._adapter.auth(
            url=url,
            use_token=use_token,
            **kwargs
        )

    def list_auth_backends(self):
        """GET /sys/auth

        :return:
        :rtype:
        """
        return self._adapter.get('/v1/sys/auth').json()

    def enable_auth_backend(self, backend_type, description=None, mount_point=None):
        """POST /sys/auth/<mount point>

        :param backend_type:
        :type backend_type:
        :param description:
        :type description:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        if not mount_point:
            mount_point = backend_type

        params = {
            'type': backend_type,
            'description': description,
        }
        self._adapter.post('/v1/sys/auth/{0}'.format(mount_point), json=params)

    def tune_auth_backend(self, backend_type, mount_point=None, default_lease_ttl=None, max_lease_ttl=None, description=None,
                          audit_non_hmac_request_keys=None, audit_non_hmac_response_keys=None, listing_visibility=None,
                          passthrough_request_headers=None):
        """POST /sys/auth/<mount point>/tune

        :param backend_type: Name of the auth backend to modify (e.g., token, approle, etc.)
        :type backend_type: str.
        :param mount_point: The path the associated auth backend is mounted under.
        :type mount_point: str.
        :param description: Specifies the description of the mount. This overrides the current stored value, if any.
        :type description: str.
        :param default_lease_ttl:
        :type default_lease_ttl: int.
        :param max_lease_ttl:
        :type max_lease_ttl: int.
        :param audit_non_hmac_request_keys: Specifies the comma-separated list of keys that will not be HMAC'd by
            audit devices in the request data object.
        :type audit_non_hmac_request_keys: list.
        :param audit_non_hmac_response_keys: Specifies the comma-separated list of keys that will not be HMAC'd
            by audit devices in the response data object.
        :type audit_non_hmac_response_keys: list.
        :param listing_visibility: Specifies whether to show this mount in the UI-specific listing endpoint.
            Valid values are "unauth" or "".
        :type listing_visibility: str.
        :param passthrough_request_headers: Comma-separated list of headers to whitelist and pass from the request
            to the backend.
        :type passthrough_request_headers: list.
        :return: The JSON response from Vault
        :rtype: dict.
        """
        if not mount_point:
            mount_point = backend_type
        # All parameters are optional for this method. Until/unless we include input validation, we simply loop over the
        # parameters and add which parameters are set.
        optional_parameters = [
            'default_lease_ttl',
            'max_lease_ttl',
            'description',
            'audit_non_hmac_request_keys',
            'audit_non_hmac_response_keys',
            'listing_visibility',
            'passthrough_request_headers',
        ]
        params = {}
        for optional_parameter in optional_parameters:
            if locals().get(optional_parameter) is not None:
                params[optional_parameter] = locals().get(optional_parameter)
        return self._adapter.post('/v1/sys/auth/{0}/tune'.format(mount_point), json=params)

    def get_auth_backend_tuning(self, backend_type, mount_point=None):
        """GET /sys/auth/<mount point>/tune

        :param backend_type: Name of the auth backend to modify (e.g., token, approle, etc.)
        :type backend_type: str.
        :param mount_point: The path the associated auth backend is mounted under.
        :type mount_point: str.
        :return: The JSON response from Vault
        :rtype: dict.
        """
        if not mount_point:
            mount_point = backend_type

        return self._adapter.get('/v1/sys/auth/{0}/tune'.format(mount_point)).json()

    def disable_auth_backend(self, mount_point):
        """DELETE /sys/auth/<mount point>

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        self._adapter.delete('/v1/sys/auth/{0}'.format(mount_point))

    def create_role(self, role_name, mount_point='approle', **kwargs):
        """POST /auth/<mount_point>/role/<role name>

        :param role_name:
        :type role_name:
        :param mount_point:
        :type mount_point:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        return self._adapter.post('/v1/auth/{0}/role/{1}'.format(mount_point, role_name), json=kwargs)

    def delete_role(self, role_name, mount_point='approle'):
        """DELETE /auth/<mount_point>/role/<role name>

        :param role_name:
        :type role_name:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """

        return self._adapter.delete('/v1/auth/{0}/role/{1}'.format(mount_point, role_name))

    def list_roles(self, mount_point='approle'):
        """GET /auth/<mount_point>/role

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """

        return self._adapter.get('/v1/auth/{0}/role?list=true'.format(mount_point)).json()

    def get_role_id(self, role_name, mount_point='approle'):
        """GET /auth/<mount_point>/role/<role name>/role-id

        :param role_name:
        :type role_name:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """

        url = '/v1/auth/{0}/role/{1}/role-id'.format(mount_point, role_name)
        return self._adapter.get(url).json()['data']['role_id']

    def set_role_id(self, role_name, role_id, mount_point='approle'):
        """POST /auth/<mount_point>/role/<role name>/role-id

        :param role_name:
        :type role_name:
        :param role_id:
        :type role_id:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """

        url = '/v1/auth/{0}/role/{1}/role-id'.format(mount_point, role_name)
        params = {
            'role_id': role_id
        }
        return self._adapter.post(url, json=params)

    def get_role(self, role_name, mount_point='approle'):
        """GET /auth/<mount_point>/role/<role name>

        :param role_name:
        :type role_name:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.get('/v1/auth/{0}/role/{1}'.format(mount_point, role_name)).json()

    def create_role_secret_id(self, role_name, meta=None, cidr_list=None, wrap_ttl=None, mount_point='approle'):
        """POST /auth/<mount_point>/role/<role name>/secret-id

        :param role_name:
        :type role_name:
        :param meta:
        :type meta:
        :param cidr_list:
        :type cidr_list:
        :param wrap_ttl:
        :type wrap_ttl:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """

        url = '/v1/auth/{0}/role/{1}/secret-id'.format(mount_point, role_name)
        params = {}
        if meta is not None:
            params['metadata'] = json.dumps(meta)
        if cidr_list is not None:
            params['cidr_list'] = cidr_list
        return self._adapter.post(url, json=params, wrap_ttl=wrap_ttl).json()

    def get_role_secret_id(self, role_name, secret_id, mount_point='approle'):
        """POST /auth/<mount_point>/role/<role name>/secret-id/lookup

        :param role_name:
        :type role_name:
        :param secret_id:
        :type secret_id:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/auth/{0}/role/{1}/secret-id/lookup'.format(mount_point, role_name)
        params = {
            'secret_id': secret_id
        }
        return self._adapter.post(url, json=params).json()

    def list_role_secrets(self, role_name, mount_point='approle'):
        """GET /auth/<mount_point>/role/<role name>/secret-id?list=true

        :param role_name:
        :type role_name:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/auth/{0}/role/{1}/secret-id?list=true'.format(mount_point, role_name)
        return self._adapter.get(url).json()

    def get_role_secret_id_accessor(self, role_name, secret_id_accessor, mount_point='approle'):
        """POST /auth/<mount_point>/role/<role name>/secret-id-accessor/lookup

        :param role_name:
        :type role_name:
        :param secret_id_accessor:
        :type secret_id_accessor:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/auth/{0}/role/{1}/secret-id-accessor/lookup'.format(mount_point, role_name)
        params = {'secret_id_accessor': secret_id_accessor}
        return self._adapter.post(url, json=params).json()

    def delete_role_secret_id(self, role_name, secret_id, mount_point='approle'):
        """POST /auth/<mount_point>/role/<role name>/secret-id/destroy

        :param role_name:
        :type role_name:
        :param secret_id:
        :type secret_id:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/auth/{0}/role/{1}/secret-id/destroy'.format(mount_point, role_name)
        params = {
            'secret_id': secret_id
        }
        return self._adapter.post(url, json=params)

    def delete_role_secret_id_accessor(self, role_name, secret_id_accessor, mount_point='approle'):
        """DELETE /auth/<mount_point>/role/<role name>/secret-id/<secret_id_accessor>

        :param role_name:
        :type role_name:
        :param secret_id_accessor:
        :type secret_id_accessor:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/auth/{0}/role/{1}/secret-id-accessor/{2}'.format(mount_point, role_name, secret_id_accessor)
        return self._adapter.delete(url)

    def create_role_custom_secret_id(self, role_name, secret_id, meta=None, mount_point='approle'):
        """POST /auth/<mount_point>/role/<role name>/custom-secret-id

        :param role_name:
        :type role_name:
        :param secret_id:
        :type secret_id:
        :param meta:
        :type meta:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/auth/{0}/role/{1}/custom-secret-id'.format(mount_point, role_name)
        params = {
            'secret_id': secret_id
        }
        if meta is not None:
            params['meta'] = meta
        return self._adapter.post(url, json=params).json()

    def auth_approle(self, role_id, secret_id=None, mount_point='approle', use_token=True):
        """POST /auth/<mount_point>/login

        :param role_id:
        :type role_id:
        :param secret_id:
        :type secret_id:
        :param mount_point:
        :type mount_point:
        :param use_token:
        :type use_token:
        :return:
        :rtype:
        """
        params = {
            'role_id': role_id
        }
        if secret_id is not None:
            params['secret_id'] = secret_id

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def create_kubernetes_configuration(self, kubernetes_host, kubernetes_ca_cert=None, token_reviewer_jwt=None, pem_keys=None, mount_point='kubernetes'):
        """POST /auth/<mount_point>/config

        :param kubernetes_host: A host:port pair, or a URL to the base of the Kubernetes API server.
        :type kubernetes_host: str.
        :param kubernetes_ca_cert: PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API.
        :type kubernetes_ca_cert: str.
        :param token_reviewer_jwt: A service account JWT used to access the TokenReview API to validate other
            JWTs during login. If not set the JWT used for login will be used to access the API.
        :type token_reviewer_jwt: str.
        :param pem_keys: Optional list of PEM-formated public keys or certificates used to verify the signatures of
            Kubernetes service account JWTs. If a certificate is given, its public key will be extracted. Not every
            installation of Kubernetes exposes these keys.
        :type pem_keys: list.
        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Will be an empty body with a 204 status code upon success
        :rtype: requests.Response.
        """
        params = {
            'kubernetes_host': kubernetes_host,
            'kubernetes_ca_cert': kubernetes_ca_cert,
        }

        if token_reviewer_jwt is not None:
            params['token_reviewer_jwt'] = token_reviewer_jwt
        if pem_keys is not None:
            params['pem_keys'] = pem_keys

        url = 'v1/auth/{0}/config'.format(mount_point)
        return self._adapter.post(url, json=params)

    def get_kubernetes_configuration(self, mount_point='kubernetes'):
        """GET /auth/<mount_point>/config

        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Parsed JSON response from the config GET request
        :rtype: dict.
        """

        url = '/v1/auth/{0}/config'.format(mount_point)
        return self._adapter.get(url).json()

    def create_kubernetes_role(self, name, bound_service_account_names, bound_service_account_namespaces, ttl="",
                               max_ttl="", period="", policies=None, mount_point='kubernetes'):
        """POST /auth/<mount_point>/role/:name

        :param name: Name of the role.
        :type name: str.
        :param bound_service_account_names: List of service account names able to access this role. If set to "*" all
            names are allowed, both this and bound_service_account_namespaces can not be "*".
        :type bound_service_account_names: list.
        :param bound_service_account_namespaces: List of namespaces allowed to access this role. If set to "*" all
            namespaces are allowed, both this and bound_service_account_names can not be set to "*".
        :type bound_service_account_namespaces: list.
        :param ttl: The TTL period of tokens issued using this role in seconds.
        :type ttl: str.
        :param max_ttl: The maximum allowed lifetime of tokens issued in seconds using this role.
        :type max_ttl: str.
        :param period: If set, indicates that the token generated using this role should never expire.
            The token should be renewed within the duration specified by this value. At each renewal, the token's TTL will
            be set to the value of this parameter.
        :type period: str.
        :param policies: Policies to be set on tokens issued using this role
        :type policies: list.
        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Will be an empty body with a 204 status code upon success
        :rtype: requests.Response.
        """
        if bound_service_account_names == '*' and bound_service_account_namespaces == '*':
            error_message = 'bound_service_account_names and bound_service_account_namespaces can not both be set to "*"'
            raise exceptions.ParamValidationError(error_message)

        params = {
            'bound_service_account_names': bound_service_account_names,
            'bound_service_account_namespaces': bound_service_account_namespaces,
            'ttl': ttl,
            'max_ttl': max_ttl,
            'period': period,
            'policies': policies,
        }
        url = 'v1/auth/{0}/role/{1}'.format(mount_point, name)
        return self._adapter.post(url, json=params)

    def get_kubernetes_role(self, name, mount_point='kubernetes'):
        """GET /auth/<mount_point>/role/:name

        :param name: Name of the role.
        :type name: str.
        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Parsed JSON response from the read role GET request
        :rtype: dict.
        """

        url = 'v1/auth/{0}/role/{1}'.format(mount_point, name)
        return self._adapter.get(url).json()

    def list_kubernetes_roles(self, mount_point='kubernetes'):
        """GET /auth/<mount_point>/role?list=true

        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Parsed JSON response from the list roles GET request.
        :rtype: dict.
        """

        url = 'v1/auth/{0}/role?list=true'.format(mount_point)
        return self._adapter.get(url).json()

    def delete_kubernetes_role(self, role, mount_point='kubernetes'):
        """DELETE /auth/<mount_point>/role/:role

        :type role: Name of the role.
        :param role: str.
        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Will be an empty body with a 204 status code upon success.
        :rtype: requests.Response.
        """

        url = 'v1/auth/{0}/role/{1}'.format(mount_point, role)
        return self._adapter.delete(url)

    def auth_kubernetes(self, role, jwt, use_token=True, mount_point='kubernetes'):
        """POST /auth/<mount_point>/login

        :param role: Name of the role against which the login is being attempted.
        :type role: str.
        :param jwt: Signed JSON Web Token (JWT) for authenticating a service account.
        :type jwt: str.
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the current Client class instance.
        :type use_token: bool.
        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Parsed JSON response from the config POST request.
        :rtype: dict.
        """
        params = {
            'role': role,
            'jwt': jwt
        }
        url = 'v1/auth/{0}/login'.format(mount_point)
        return self.auth(url, json=params, use_token=use_token)

    def transit_create_key(self, name, convergent_encryption=None, derived=None, exportable=None,
                           key_type=None, mount_point='transit'):
        """POST /<mount_point>/keys/<name>

        :param name:
        :type name:
        :param convergent_encryption:
        :type convergent_encryption:
        :param derived:
        :type derived:
        :param exportable:
        :type exportable:
        :param key_type:
        :type key_type:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
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

        return self._adapter.post(url, json=params)

    def transit_read_key(self, name, mount_point='transit'):
        """GET /<mount_point>/keys/<name>

        :param name:
        :type name:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/{0}/keys/{1}'.format(mount_point, name)
        return self._adapter.get(url).json()

    def transit_list_keys(self, mount_point='transit'):
        """GET /<mount_point>/keys?list=true

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/{0}/keys?list=true'.format(mount_point)
        return self._adapter.get(url).json()

    def transit_delete_key(self, name, mount_point='transit'):
        """DELETE /<mount_point>/keys/<name>

        :param name:
        :type name:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/{0}/keys/{1}'.format(mount_point, name)
        return self._adapter.delete(url)

    def transit_update_key(self, name, min_decryption_version=None, min_encryption_version=None, deletion_allowed=None,
                           mount_point='transit'):
        """POST /<mount_point>/keys/<name>/config

        :param name:
        :type name:
        :param min_decryption_version:
        :type min_decryption_version:
        :param min_encryption_version:
        :type min_encryption_version:
        :param deletion_allowed:
        :type deletion_allowed:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/{0}/keys/{1}/config'.format(mount_point, name)
        params = {}
        if min_decryption_version is not None:
            params['min_decryption_version'] = min_decryption_version
        if min_encryption_version is not None:
            params['min_encryption_version'] = min_encryption_version
        if deletion_allowed is not None:
            params['deletion_allowed'] = deletion_allowed

        return self._adapter.post(url, json=params)

    def transit_rotate_key(self, name, mount_point='transit'):
        """POST /<mount_point>/keys/<name>/rotate

        :param name:
        :type name:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/{0}/keys/{1}/rotate'.format(mount_point, name)
        return self._adapter.post(url)

    def transit_export_key(self, name, key_type, version=None, mount_point='transit'):
        """GET /<mount_point>/export/<key_type>/<name>(/<version>)

        :param name:
        :type name:
        :param key_type:
        :type key_type:
        :param version:
        :type version:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        if version is not None:
            url = '/v1/{0}/export/{1}/{2}/{3}'.format(mount_point, key_type, name, version)
        else:
            url = '/v1/{0}/export/{1}/{2}'.format(mount_point, key_type, name)
        return self._adapter.get(url).json()

    def transit_encrypt_data(self, name, plaintext, context=None, key_version=None, nonce=None, batch_input=None,
                             key_type=None, convergent_encryption=None, mount_point='transit'):
        """POST /<mount_point>/encrypt/<name>

        :param name:
        :type name:
        :param plaintext:
        :type plaintext:
        :param context:
        :type context:
        :param key_version:
        :type key_version:
        :param nonce:
        :type nonce:
        :param batch_input:
        :type batch_input:
        :param key_type:
        :type key_type:
        :param convergent_encryption:
        :type convergent_encryption:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
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

        return self._adapter.post(url, json=params).json()

    def transit_decrypt_data(self, name, ciphertext, context=None, nonce=None, batch_input=None, mount_point='transit'):
        """POST /<mount_point>/decrypt/<name>

        :param name:
        :type name:
        :param ciphertext:
        :type ciphertext:
        :param context:
        :type context:
        :param nonce:
        :type nonce:
        :param batch_input:
        :type batch_input:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
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

        return self._adapter.post(url, json=params).json()

    def transit_rewrap_data(self, name, ciphertext, context=None, key_version=None, nonce=None, batch_input=None,
                            mount_point='transit'):
        """POST /<mount_point>/rewrap/<name>

        :param name:
        :type name:
        :param ciphertext:
        :type ciphertext:
        :param context:
        :type context:
        :param key_version:
        :type key_version:
        :param nonce:
        :type nonce:
        :param batch_input:
        :type batch_input:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
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

        return self._adapter.post(url, json=params).json()

    def transit_generate_data_key(self, name, key_type, context=None, nonce=None, bits=None, mount_point='transit'):
        """POST /<mount_point>/datakey/<type>/<name>

        :param name:
        :type name:
        :param key_type:
        :type key_type:
        :param context:
        :type context:
        :param nonce:
        :type nonce:
        :param bits:
        :type bits:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        url = '/v1/{0}/datakey/{1}/{2}'.format(mount_point, key_type, name)
        params = {}
        if context is not None:
            params['context'] = context
        if nonce is not None:
            params['nonce'] = nonce
        if bits is not None:
            params['bits'] = bits

        return self._adapter.post(url, json=params).json()

    def transit_generate_rand_bytes(self, data_bytes=None, output_format=None, mount_point='transit'):
        """POST /<mount_point>/random(/<data_bytes>)

        :param data_bytes:
        :type data_bytes:
        :param output_format:
        :type output_format:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        if data_bytes is not None:
            url = '/v1/{0}/random/{1}'.format(mount_point, data_bytes)
        else:
            url = '/v1/{0}/random'.format(mount_point)

        params = {}
        if output_format is not None:
            params["format"] = output_format

        return self._adapter.post(url, json=params).json()

    def transit_hash_data(self, hash_input, algorithm=None, output_format=None, mount_point='transit'):
        """POST /<mount_point>/hash(/<algorithm>)

        :param hash_input:
        :type hash_input:
        :param algorithm:
        :type algorithm:
        :param output_format:
        :type output_format:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
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

        return self._adapter.post(url, json=params).json()

    def transit_generate_hmac(self, name, hmac_input, key_version=None, algorithm=None, mount_point='transit'):
        """POST /<mount_point>/hmac/<name>(/<algorithm>)

        :param name:
        :type name:
        :param hmac_input:
        :type hmac_input:
        :param key_version:
        :type key_version:
        :param algorithm:
        :type algorithm:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
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

        return self._adapter.post(url, json=params).json()

    def transit_sign_data(self, name, input_data, key_version=None, algorithm=None, context=None, prehashed=None,
                          mount_point='transit', signature_algorithm='pss'):
        """POST /<mount_point>/sign/<name>(/<algorithm>)

        :param name:
        :type name:
        :param input_data:
        :type input_data:
        :param key_version:
        :type key_version:
        :param algorithm:
        :type algorithm:
        :param context:
        :type context:
        :param prehashed:
        :type prehashed:
        :param mount_point:
        :type mount_point:
        :param signature_algorithm:
        :type signature_algorithm:
        :return:
        :rtype:
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
        params['signature_algorithm'] = signature_algorithm

        return self._adapter.post(url, json=params).json()

    def transit_verify_signed_data(self, name, input_data, algorithm=None, signature=None, hmac=None, context=None,
                                   prehashed=None, mount_point='transit', signature_algorithm='pss'):
        """POST /<mount_point>/verify/<name>(/<algorithm>)

        :param name:
        :type name:
        :param input_data:
        :type input_data:
        :param algorithm:
        :type algorithm:
        :param signature:
        :type signature:
        :param hmac:
        :type hmac:
        :param context:
        :type context:
        :param prehashed:
        :type prehashed:
        :param mount_point:
        :type mount_point:
        :param signature_algorithm:
        :type signature_algorithm:
        :return:
        :rtype:
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
        params['signature_algorithm'] = signature_algorithm

        return self._adapter.post(url, json=params).json()

    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=api.auth.Ldap.login,
    )
    def auth_ldap(self, *args, **kwargs):
        return self.ldap.login(*args, **kwargs)

    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=api.auth.Github.login,
    )
    def auth_github(self, *args, **kwargs):
        return self.github.login(*args, **kwargs)

    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=adapters.Request.close,
    )
    def close(self):
        return self._adapter.close()

    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=adapters.Request.get,
    )
    def _get(self, *args, **kwargs):
        return self._adapter.get(*args, **kwargs)

    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=adapters.Request.post,
    )
    def _post(self, *args, **kwargs):
        return self._adapter.post(*args, **kwargs)

    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=adapters.Request.put,
    )
    def _put(self, *args, **kwargs):
        return self._adapter.put(*args, **kwargs)

    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=adapters.Request.delete,
    )
    def _delete(self, *args, **kwargs):
        return self._adapter.delete(*args, **kwargs)

    @staticmethod
    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=adapters.Request.urljoin,
    )
    def urljoin(*args):
        return adapters.Request.urljoin(*args)

    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=adapters.Request.request,
    )
    def __request(self, *args, **kwargs):
        return self._adapter.request(*args, **kwargs)

    @utils.deprecated_method(
        to_be_removed_in_version='0.8.0',
        new_method=utils.raise_for_error,
    )
    def __raise_error(self, *args, **kwargs):
        utils.raise_for_error(*args, **kwargs)

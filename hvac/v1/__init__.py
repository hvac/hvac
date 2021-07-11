from __future__ import unicode_literals

import json
import os
from base64 import b64encode

from hvac import adapters, api, aws_utils, exceptions, utils
from hvac.constants.client import (
    DEFAULT_URL,
    DEPRECATED_PROPERTIES,
    VAULT_CACERT,
    VAULT_CAPATH,
    VAULT_CLIENT_CERT,
    VAULT_CLIENT_KEY,
)
from hvac.utils import generate_property_deprecation_message

try:
    import hcl

    has_hcl_parser = True
except ImportError:
    has_hcl_parser = False


class Client(object):
    """The hvac Client class for HashiCorp's Vault."""

    def __init__(
        self,
        url=None,
        token=None,
        cert=None,
        verify=True,
        timeout=30,
        proxies=None,
        allow_redirects=True,
        session=None,
        adapter=adapters.JSONAdapter,
        namespace=None,
        **kwargs
    ):
        """Creates a new hvac client instance.

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
        :param proxies: Proxies to use when performing requests.
            See: http://docs.python-requests.org/en/master/user/advanced/#proxies
        :type proxies: dict
        :param allow_redirects: Whether to follow redirects when sending requests to Vault.
        :type allow_redirects: bool
        :param session: Optional session object to use when performing request.
        :type session: request.Session
        :param adapter: Optional class to be used for performing requests. If none is provided, defaults to
            hvac.adapters.JSONRequest
        :type adapter: hvac.adapters.Adapter
        :param kwargs: Additional parameters to pass to the adapter constructor.
        :type kwargs: dict
        :param namespace: Optional Vault Namespace.
        :type namespace: str
        """

        token = token if token is not None else utils.get_token_from_env()
        url = url if url else os.getenv("VAULT_ADDR", DEFAULT_URL)

        if cert is not None and VAULT_CLIENT_CERT:
            cert = "\n".join(
                [
                    VAULT_CLIENT_CERT,
                    VAULT_CLIENT_KEY,
                ]
            )

        # Consider related CA env vars _only if_ no argument is passed in under the
        # `verify` parameter.
        if verify is not None:
            # Reference: https://www.vaultproject.io/docs/commands#vault_cacert
            # Note: "[VAULT_CACERT] takes precedence over VAULT_CAPATH." and thus we
            # check for VAULT_CAPATH _first_.
            if VAULT_CAPATH:
                verify = VAULT_CAPATH
            if VAULT_CACERT:
                verify = VAULT_CACERT

        self._adapter = adapter(
            base_uri=url,
            token=token,
            cert=cert,
            verify=verify,
            timeout=timeout,
            proxies=proxies,
            allow_redirects=allow_redirects,
            session=session,
            namespace=namespace,
            **kwargs
        )

        # Instantiate API classes to be exposed as properties on this class starting with auth method classes.
        self._auth = api.AuthMethods(adapter=self._adapter)
        self._secrets = api.SecretsEngines(adapter=self._adapter)
        self._sys = api.SystemBackend(adapter=self._adapter)

    def __getattr__(self, name):
        return utils.getattr_with_deprecated_properties(
            obj=self, item=name, deprecated_properties=DEPRECATED_PROPERTIES
        )

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
    def auth(self):
        """Accessor for the Client instance's auth methods. Provided via the :py:class:`hvac.api.AuthMethods` class.
        :return: This Client instance's associated Auth instance.
        :rtype: hvac.api.AuthMethods
        """
        return self._auth

    @property
    def secrets(self):
        """Accessor for the Client instance's secrets engines. Provided via the :py:class:`hvac.api.SecretsEngines` class.

        :return: This Client instance's associated SecretsEngines instance.
        :rtype: hvac.api.SecretsEngines
        """
        return self._secrets

    @property
    def sys(self):
        """Accessor for the Client instance's system backend methods.
        Provided via the :py:class:`hvac.api.SystemBackend` class.

        :return: This Client instance's associated SystemBackend instance.
        :rtype: hvac.api.SystemBackend
        """
        return self._sys

    @property
    def generate_root_status(self):
        return self.sys.read_root_generation_progress()

    @property
    def key_status(self):
        """GET /sys/key-status

        :return: Information about the current encryption key used by Vault.
        :rtype: dict
        """
        return self.sys.get_encryption_key_status()["data"]

    @property
    def rekey_status(self):
        return self.sys.read_rekey_progress()

    @property
    def ha_status(self):
        """Read the high availability status and current leader instance of Vault.

        :return: The JSON response returned by read_leader_status()
        :rtype: dict
        """
        return self.sys.read_leader_status()

    @property
    def seal_status(self):
        """Read the seal status of the Vault.

        This is an unauthenticated endpoint.

        Supported methods:
            GET: /sys/seal-status. Produces: 200 application/json

        :return: The JSON response of the request.
        :rtype: dict
        """
        return self.sys.read_seal_status()

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
            return self._adapter.get("/v1/{0}".format(path), wrap_ttl=wrap_ttl)
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
            payload = {"list": True}
            return self._adapter.get("/v1/{0}".format(path), params=payload)
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
        return self._adapter.post(
            "/v1/{0}".format(path), json=kwargs, wrap_ttl=wrap_ttl
        )

    def delete(self, path):
        """DELETE /<path>

        :param path:
        :type path:
        :return:
        :rtype:
        """
        self._adapter.delete("/v1/{0}".format(path))

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
            policy = self.sys.read_policy(name=name)["data"]["rules"]
        except exceptions.InvalidPath:
            return None

        if parse:
            if not has_hcl_parser:
                raise ImportError("pyhcl is required for policy parsing")
            policy = hcl.loads(policy)

        return policy

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Token.revoke_self,
    )
    def revoke_self_token(self):
        """PUT /auth/token/revoke-self

        :return:
        :rtype:
        """
        self._adapter.put("/v1/auth/token/revoke-self")

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Token.create,
    )
    def create_token(
        self,
        role=None,
        token_id=None,
        policies=None,
        meta=None,
        no_parent=False,
        lease=None,
        display_name=None,
        num_uses=None,
        no_default_policy=False,
        ttl=None,
        orphan=False,
        wrap_ttl=None,
        renewable=None,
        explicit_max_ttl=None,
        period=None,
        token_type=None,
    ):
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
        :param token_type:
        :type token_type:
        :return:
        :rtype:
        """
        params = {
            "id": token_id,
            "policies": policies,
            "meta": meta,
            "no_parent": no_parent,
            "display_name": display_name,
            "num_uses": num_uses,
            "no_default_policy": no_default_policy,
            "renewable": renewable,
        }

        if lease:
            params["lease"] = lease
        else:
            params["ttl"] = ttl
            params["explicit_max_ttl"] = explicit_max_ttl

        if explicit_max_ttl:
            params["explicit_max_ttl"] = explicit_max_ttl

        if period:
            params["period"] = period
        if token_type:
            params["type"] = token_type

        if orphan:
            return self._adapter.post(
                "/v1/auth/token/create-orphan", json=params, wrap_ttl=wrap_ttl
            )
        elif role:
            return self._adapter.post(
                "/v1/auth/token/create/{0}".format(role), json=params, wrap_ttl=wrap_ttl
            )
        else:
            return self._adapter.post(
                "/v1/auth/token/create", json=params, wrap_ttl=wrap_ttl
            )

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
            "token": token,
        }
        accessor_param = {
            "accessor": token,
        }
        if token:
            if accessor:
                path = "/v1/auth/token/lookup-accessor"
                return self._adapter.post(path, json=accessor_param, wrap_ttl=wrap_ttl)
            else:
                path = "/v1/auth/token/lookup"
                return self._adapter.post(path, json=token_param)
        else:
            path = "/v1/auth/token/lookup-self"
            return self._adapter.get(path, wrap_ttl=wrap_ttl)

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
            params = {"accessor": token}
            self._adapter.post("/v1/auth/token/revoke-accessor", json=params)
        elif orphan:
            params = {"token": token}
            self._adapter.post("/v1/auth/token/revoke-orphan", json=params)
        else:
            params = {"token": token}
            self._adapter.post("/v1/auth/token/revoke", json=params)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
    )
    def revoke_token_prefix(self, prefix):
        """POST /auth/token/revoke-prefix/<prefix>

        :param prefix:
        :type prefix:
        :return:
        :rtype:
        """
        self._adapter.post("/v1/auth/token/revoke-prefix/{0}".format(prefix))

    def renew_token(self, token=None, increment=None, wrap_ttl=None):
        """POST /auth/token/renew

        POST /auth/token/renew-self

        :param token:
        :type token:
        :param increment:
        :type increment:
        :param wrap_ttl:
        :type wrap_ttl:
        :return:
        :rtype:

        For calls expecting to hit the renew-self endpoint please use the "renew_self_token" method instead
        """
        params = {
            "increment": increment,
        }

        if token is not None:
            params["token"] = token
            return self._adapter.post(
                "/v1/auth/token/renew", json=params, wrap_ttl=wrap_ttl
            )
        else:
            generate_property_deprecation_message(
                "1.0.0",
                "renew_token() without token param",
                "renew_self_token() without token param",
                "renew_self_token",
            )
            return self.renew_self_token(increment=increment, wrap_ttl=wrap_ttl)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Token.renew_self,
    )
    def renew_self_token(self, increment=None, wrap_ttl=None):
        """
        POST /auth/token/renew-self

        :param increment:
        :type increment:
        :param wrap_ttl:
        :type wrap_ttl:
        :return:
        :rtype:
        """
        params = {
            "increment": increment,
        }

        return self._adapter.post(
            "/v1/auth/token/renew-self", json=params, wrap_ttl=wrap_ttl
        )

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Token.create_or_update_role,
    )
    def create_token_role(
        self,
        role,
        allowed_policies=None,
        disallowed_policies=None,
        orphan=None,
        period=None,
        renewable=None,
        path_suffix=None,
        explicit_max_ttl=None,
    ):
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
            "allowed_policies": allowed_policies,
            "disallowed_policies": disallowed_policies,
            "orphan": orphan,
            "period": period,
            "renewable": renewable,
            "path_suffix": path_suffix,
            "explicit_max_ttl": explicit_max_ttl,
        }
        return self._adapter.post("/v1/auth/token/roles/{0}".format(role), json=params)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Token.read_role,
    )
    def token_role(self, role):
        """Returns the named token role.

        :param role:
        :type role:
        :return:
        :rtype:
        """
        return self.read("auth/token/roles/{0}".format(role))

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Token.delete_role,
    )
    def delete_token_role(self, role):
        """Deletes the named token role.

        :param role:
        :type role:
        :return:
        :rtype:
        """
        return self.delete("auth/token/roles/{0}".format(role))

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Token.list_roles,
    )
    def list_token_roles(self):
        """GET /auth/token/roles?list=true

        :return:
        :rtype:
        """
        return self.list("auth/token/roles")

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

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Userpass.login,
    )
    def auth_userpass(
        self, username, password, mount_point="userpass", use_token=True, **kwargs
    ):
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
            "password": password,
        }

        params.update(kwargs)

        return self.login(
            "/v1/auth/{0}/login/{1}".format(mount_point, username),
            json=params,
            use_token=use_token,
        )

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Userpass.create_or_update_user,
    )
    def create_userpass(
        self, username, password, policies, mount_point="userpass", **kwargs
    ):
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
            policies = ",".join(policies)

        params = {"password": password, "policies": policies}
        params.update(kwargs)

        return self._adapter.post(
            "/v1/auth/{}/users/{}".format(mount_point, username), json=params
        )

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Userpass.list_user,
    )
    def list_userpass(self, mount_point="userpass"):
        """GET /auth/<mount point>/users?list=true

        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        try:
            return self._adapter.get(
                "/v1/auth/{}/users".format(mount_point), params={"list": True}
            )
        except exceptions.InvalidPath:
            return None

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Userpass.read_user,
    )
    def read_userpass(self, username, mount_point="userpass"):
        """GET /auth/<mount point>/users/<username>

        :param username:
        :type username:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.get("/v1/auth/{}/users/{}".format(mount_point, username))

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Userpass.create_or_update_user,
    )
    def update_userpass_policies(self, username, policies, mount_point="userpass"):
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
            policies = ",".join(policies)

        params = {"policies": policies}

        return self._adapter.post(
            "/v1/auth/{}/users/{}/policies".format(mount_point, username), json=params
        )

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Userpass.update_password_on_user,
    )
    def update_userpass_password(self, username, password, mount_point="userpass"):
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
        params = {"password": password}
        return self._adapter.post(
            "/v1/auth/{}/users/{}/password".format(mount_point, username), json=params
        )

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Userpass.delete_user,
    )
    def delete_userpass(self, username, mount_point="userpass"):
        """DELETE /auth/<mount point>/users/<username>

        :param username:
        :type username:
        :param mount_point:
        :type mount_point:
        :return:
        :rtype:
        """
        return self._adapter.delete(
            "/v1/auth/{}/users/{}".format(mount_point, username)
        )

    def auth_cubbyhole(self, token):
        """Perform a login request with a wrapped token.

        Stores the unwrapped token in the resulting Vault response for use by the :py:meth:`hvac.adapters.Adapter`
            instance under the _adapater Client attribute.

        :param token: Wrapped token
        :type token: str | unicode
        :return: The (JSON decoded) response of the auth request
        :rtype: dict
        """
        self.token = token
        return self.login("/v1/sys/wrapping/unwrap")

    def login(self, url, use_token=True, **kwargs):
        """Perform a login request.

        Associated request is typically to a path prefixed with "/v1/auth") and optionally stores the client token sent
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
        return self._adapter.login(url=url, use_token=use_token, **kwargs)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Kubernetes.configure,
    )
    def create_kubernetes_configuration(
        self,
        kubernetes_host,
        kubernetes_ca_cert=None,
        token_reviewer_jwt=None,
        pem_keys=None,
        mount_point="kubernetes",
    ):
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
            "kubernetes_host": kubernetes_host,
            "kubernetes_ca_cert": kubernetes_ca_cert,
        }

        if token_reviewer_jwt is not None:
            params["token_reviewer_jwt"] = token_reviewer_jwt
        if pem_keys is not None:
            params["pem_keys"] = pem_keys

        url = "v1/auth/{0}/config".format(mount_point)
        return self._adapter.post(url, json=params)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Kubernetes.read_config,
    )
    def get_kubernetes_configuration(self, mount_point="kubernetes"):
        """GET /auth/<mount_point>/config

        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Parsed JSON response from the config GET request
        :rtype: dict.
        """

        url = "/v1/auth/{0}/config".format(mount_point)
        return self._adapter.get(url)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Kubernetes.create_role,
    )
    def create_kubernetes_role(
        self,
        name,
        bound_service_account_names,
        bound_service_account_namespaces,
        ttl="",
        max_ttl="",
        period="",
        policies=None,
        token_type="",
        mount_point="kubernetes",
    ):
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
        :type token_type: str.
        :return: Will be an empty body with a 204 status code upon success
        :rtype: requests.Response.
        """
        if (
            bound_service_account_names == "*"
            and bound_service_account_namespaces == "*"
        ):
            error_message = 'bound_service_account_names and bound_service_account_namespaces can not both be set to "*"'
            raise exceptions.ParamValidationError(error_message)

        params = {
            "bound_service_account_names": bound_service_account_names,
            "bound_service_account_namespaces": bound_service_account_namespaces,
            "ttl": ttl,
            "max_ttl": max_ttl,
            "period": period,
            "policies": policies,
        }
        if token_type:
            params["token_type"] = token_type

        url = "v1/auth/{0}/role/{1}".format(mount_point, name)
        return self._adapter.post(url, json=params)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Kubernetes.read_role,
    )
    def get_kubernetes_role(self, name, mount_point="kubernetes"):
        """GET /auth/<mount_point>/role/:name

        :param name: Name of the role.
        :type name: str.
        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Parsed JSON response from the read role GET request
        :rtype: dict.
        """

        url = "v1/auth/{0}/role/{1}".format(mount_point, name)
        return self._adapter.get(url)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Kubernetes.list_roles,
    )
    def list_kubernetes_roles(self, mount_point="kubernetes"):
        """GET /auth/<mount_point>/role?list=true

        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Parsed JSON response from the list roles GET request.
        :rtype: dict.
        """

        url = "v1/auth/{0}/role?list=true".format(mount_point)
        return self._adapter.get(url)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Kubernetes.delete_role,
    )
    def delete_kubernetes_role(self, role, mount_point="kubernetes"):
        """DELETE /auth/<mount_point>/role/:role

        :type role: Name of the role.
        :param role: str.
        :param mount_point: The "path" the k8s auth backend was mounted on. Vault currently defaults to "kubernetes".
        :type mount_point: str.
        :return: Will be an empty body with a 204 status code upon success.
        :rtype: requests.Response.
        """

        url = "v1/auth/{0}/role/{1}".format(mount_point, role)
        return self._adapter.delete(url)

    @utils.deprecated_method(
        to_be_removed_in_version="1.0.0",
        new_method=api.auth_methods.Kubernetes.login,
    )
    def auth_kubernetes(self, role, jwt, use_token=True, mount_point="kubernetes"):
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
        params = {"role": role, "jwt": jwt}
        url = "v1/auth/{0}/login".format(mount_point)
        return self.login(url, json=params, use_token=use_token)

    @utils.deprecated_method(
        to_be_removed_in_version="0.8.0",
        new_method=api.auth_methods.Ldap.login,
    )
    def auth_ldap(self, *args, **kwargs):
        return self.auth.ldap.login(*args, **kwargs)

    @utils.deprecated_method(
        to_be_removed_in_version="0.9.0",
        new_method=api.auth_methods.Gcp.login,
    )
    def auth_gcp(self, *args, **kwargs):
        return self.auth.gcp.login(*args, **kwargs)

    @utils.deprecated_method(
        to_be_removed_in_version="0.8.0",
        new_method=api.auth_methods.Github.login,
    )
    def auth_github(self, *args, **kwargs):
        return self.auth.github.login(*args, **kwargs)

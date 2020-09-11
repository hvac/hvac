"""SSH vault secrets backend module."""

from typing import Dict, List, Literal, Optional, Union

from hvac import exceptions, utils
from hvac.api.vault_api_base import VaultApiBase


DEFAULT_MOUNT_POINT = 'ssh'
ALLOWED_KEY_TYPES = frozenset(('otp', 'dynamic', 'ca'))
ALLOWED_RSA_KEY_BITS = 1024, 2048

VaultDuration = Union[int, str]


class Ssh(VaultApiBase):
    """
    SSH Secrets Engine.

    Reference: https://www.vaultproject.io/api-docs/secret/ssh
    """

    def create_or_update_key(
        self, name: str, key: str, mount_point: str = DEFAULT_MOUNT_POINT
    ):
        params = {'key': key}
        api_path = utils.format_url(
            '/v1/{mount_point}/keys/{name}', mount_point=mount_point, name=name
        )
        return self._adapter.post(url=api_path, json=params)

    def delete_key(self, name: str, mount_point: str = DEFAULT_MOUNT_POINT):
        api_path = utils.format_url(
            '/v1/{mount_point}/keys/{name}', mount_point=mount_point, name=name
        )
        return self._adapter.delete(url=api_path)

    def create_or_update_role(
        self,
        name: str,
        key_type: Literal['ca', 'dynamic', 'otp'],
        # This uses the order from the API docs
        key: str = None,
        admin_user=None,
        default_user=None,
        cidr_list=None,
        exclude_cidr_list=None,
        port=None,
        key_bits: Optional[Literal[1024, 2048]] = None,
        install_script=None,
        allowed_users=None,
        allowed_users_template=None,
        allowed_domains=None,
        key_options_specs=None,
        ttl: VaultDuration = None,
        max_ttl: VaultDuration = None,
        allowed_critical_options: Union[str, List[str]] = None,
        allowed_extensions: Union[str, List[str]] = None,
        default_critical_options: Dict[str, str] = None,
        default_extensions: Dict[str, str] = None,
        allow_user_certificates: bool = None,
        allow_host_certificates: bool = None,
        allow_bare_domains=None,
        allow_subdomains=None,
        allow_user_key_ids=None,
        key_id_format=None,
        allowed_user_key_lengths=None,
        algorithm_signer: Literal[
            'ssh-rsa', 'ssh-rsa-sha2-256', 'ssh-rsa-sha2-512'
        ] = None,
        mount_point: str = DEFAULT_MOUNT_POINT,
    ):
        if key_type not in ALLOWED_KEY_TYPES:
            error_msg = (
                'Invalid key_type argument provided "{}", '
                'supported types: "{}"'.format(
                    key_type, ', '.join(ALLOWED_KEY_TYPES)
                )
            )
            raise exceptions.ParamValidationError(error_msg)

        if ttl:
            ttl = str(ttl)
        if max_ttl:
            max_ttl = str(max_ttl)

        if isinstance(allowed_extensions, list):
            allowed_extensions = ','.join(allowed_extensions)
        if isinstance(allowed_critical_options, list):
            allowed_critical_options = ','.join(allowed_critical_options)

        params = {
            # Required params
            'key_type': key_type,
            # Other params
            'key': key,
            'admin_user': admin_user,
            'default_user': default_user,
            'cidr_list': cidr_list,
            'exclude_cidr_list': exclude_cidr_list,
            'port': port,
            'key_bits': key_bits,
            'install_script': install_script,
            'allowed_users': allowed_users,
            'allowed_users_template': allowed_users_template,
            'allowed_domains': allowed_domains,
            'key_options_specs': key_options_specs,
            'ttl': ttl,
            'max_ttl': max_ttl,
            'allowed_critical_options': allowed_critical_options,
            'allowed_extensions': allowed_extensions,
            'default_critical_options': default_critical_options,
            'default_extensions': default_extensions,
            'allow_user_certificates': allow_user_certificates,
            'allow_host_certificates': allow_host_certificates,
            'allow_bare_domains': allow_bare_domains,
            'allow_subdomains': allow_subdomains,
            'allow_user_key_ids': allow_user_key_ids,
            'key_id_format': key_id_format,
            'allowed_user_key_lengths': allowed_user_key_lengths,
            'algorithm_signer': algorithm_signer,
        }

        params = utils.remove_nones(params)
        api_path = utils.format_url(
            '/v1/{mount_point}/roles/{name}', mount_point=mount_point, name=name
        )
        return self._adapter.post(url=api_path, json=params)

    def read_role(self, name: str, mount_point: str = DEFAULT_MOUNT_POINT):
        """Query an existing role by the given name.

        If the role does not exist, a 404 is returned.

        Supported methods:
            GET: /{mount_point}/roles/{name}. Produces: 200 application/json

        :param name: Specifies the name of the role to read. This is part of the request URL.
        :type name: str | unicode
        :param mount_point: The 'path' the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url(
            '/v1/{mount_point}/roles/{name}',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.get(url=api_path)

    def list_roles(self, mount_point: str = DEFAULT_MOUNT_POINT):
        """List all existing roles in the secrets engine.

        Supported methods:
            LIST: /{mount_point}/roles. Produces: 200 application/json

        :param mount_point: The 'path' the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url(
            '/v1/{mount_point}/roles', mount_point=mount_point
        )
        return self._adapter.list(url=api_path)

    def delete_role(self, name: str, mount_point: str = DEFAULT_MOUNT_POINT):
        """Delete an existing role by the given name.

        If the role does not exist, a 404 is returned.

        Supported methods:
            DELETE: /{mount_point}/roles/{name}. Produces: 204 (empty body)

        :param name: the name of the role to delete. This
            is part of the request URL.
        :type name: str | unicode
        :param mount_point: The 'path' the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: httpx.Response
        """
        api_path = utils.format_url(
            '/v1/{mount_point}/roles/{name}', mount_point=mount_point, name=name
        )
        return self._adapter.delete(url=api_path)

    def configure_ca(
        self,
        private_key: str = None,
        public_key: str = None,
        generate_signing_key=True,
        mount_point: str = DEFAULT_MOUNT_POINT,
    ):
        if generate_signing_key:
            if private_key or public_key:
                raise exceptions.ParamValidationError()
            params = {'generate_signing_key': True}

        if not generate_signing_key:
            if bool(private_key) != bool(public_key):
                raise exceptions.ParamValidationError()
            params = {
                'private_key': bool(private_key),
                'public_key': bool(public_key),
            }

        api_path = utils.format_url(
            '/v1/{mount_point}/config/ca',
            mount_point=mount_point,
        )
        return self._adapter.post(url=api_path, json=params)

    def delete_ca(self, mount_point: str = DEFAULT_MOUNT_POINT):
        api_path = utils.format_url(
            '/v1/{mount_point}/config/ca',
            mount_point=mount_point,
        )
        return self._adapter.delete(url=api_path)

    def read_public_key(self, mount_point: str = DEFAULT_MOUNT_POINT):
        api_path = utils.format_url(
            '/v1/{mount_point}/config/ca',
            mount_point=mount_point,
        )
        return self._adapter.get(url=api_path)

    def sign_ca_key(
        self,
        name: str,
        public_key: str,
        ttl: VaultDuration = None,
        valid_principals: Union[str, List[str]] = None,
        cert_type: Literal['user', 'host'] = 'user',
        key_id: str = None,
        critical_options: Dict[str, str] = None,
        extensions: Dict[str, str] = None,
        #
        mount_point: str = DEFAULT_MOUNT_POINT,
    ):
        if ttl:
            ttl = str(ttl)
        if isinstance(valid_principals, list):
            valid_principals = ','.join(valid_principals)

        params = utils.remove_nones(
            {
                'public_key': public_key,
                'ttl': ttl,
                'valid_principals': valid_principals,
                'cert_type': cert_type,
                'key_id': key_id,
                'critical_options': critical_options,
                'extensions': extensions,
            }
        )

        api_path = utils.format_url(
            '/v1/{mount_point}/sign/{name}'.format(
                name=name, mount_point=mount_point
            )
        )
        return self._adapter.post(url=api_path, json=params)

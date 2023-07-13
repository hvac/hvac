#!/usr/bin/env python
"""Kerberos API methods module."""
import fnmatch
import logging
import os
import string
from os.path import isfile
from random import random
from urllib.parse import urlparse

import gssapi
import gssapi.raw as gssapi_raw
from gssapi.raw.misc import GSSError
from requests_gssapi import HTTPSPNEGOAuth
from requests_gssapi.exceptions import SPNEGOExchangeError

from hvac import utils
from hvac.api.auth_methods.ldap import Ldap as LdapAuth
from hvac.exceptions import Unauthorized

DEFAULT_MOUNT_POINT = "kerberos"
HOST_TEMPLATE = '_HOST'
ENV_KRB5_CONF = 'KRB5_CONFIG' # (optional) environment variable tells us the path to your krb5.conf file.
ENV_KRB5_CACHE = 'KRB5CCNAME'  # (optional) environment variable tells us the directory of your kerberos credential cache
SPNEGO_OID = '1.3.6.1.5.5.2'


class KerberosError(Exception):
    """
    Please keep this exception so users can differentiate between kerberos issues and general api errors.
    """
    pass


class Kerberos(LdapAuth):  # TODO for discussion do you want ldap subclassed or to be verbose and a bit redundant ?
    """Kerberos Auth Method (API).

    Reference: https://www.vaultproject.io/api/auth/kerberos/index.html
    """
    def _log(self):
        return logging.getLogger(self.__class__.)

    def configure(self, **kwargs):
        super().configure(**kwargs)
        # TODO - for discussion, what should be configurable
        # krb5_conf, etc?

    def read_configuration(self, mount_point=DEFAULT_MOUNT_POINT):
        """
        Retrieve the KERBEROS configuration for the auth method.

        Supported methods:
            GET: /auth/{mount_point}/config. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the read_configuration request.
        :rtype: dict
        """
        api_path = utils.format_url(
            "/v1/auth/{mount_point}/config", mount_point=mount_point
        )
        return self._adapter.get(
            url=api_path,
        )

    def create_or_update_group(
        self, name, policies=None, mount_point=DEFAULT_MOUNT_POINT
    ):
        """
        Create or update LDAP group policies.

        Supported methods:
            POST: /auth/{mount_point}/groups/{name}. Produces: 204 (empty body)


        :param name: The name of the LDAP group
        :type name: str | unicode
        :param policies: List of policies associated with the group. This parameter is transformed to a comma-delimited
            string before being passed to Vault.
        :type policies: list
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_or_update_group request.
        :rtype: requests.Response
        """
        return super().create_or_update_group(name, policies, mount_point)

    def list_groups(self, mount_point=DEFAULT_MOUNT_POINT):
        """
        List existing LDAP existing groups that have been created in this auth method.

        Supported methods:
            LIST: /auth/{mount_point}/groups. Produces: 200 application/json


        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_groups request.
        :rtype: dict
        """
        return super().list_groups(mount_point=mount_point)

    def read_group(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        Read policies associated with a KERBEROS group.

        Supported methods:
            GET: /auth/{mount_point}/groups/{name}. Produces: 200 application/json


        :param name: The name of the LDAP group
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the read_group request.
        :rtype: dict
        """
        return super().read_group(mount_point)

    def delete_group(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        Delete a KERBEROS group and policy association.

        Supported methods:
            DELETE: /auth/{mount_point}/groups/{name}. Produces: 204 (empty body)


        :param name: The name of the LDAP group
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_group request.
        :rtype: requests.Response
        """
        return super().delete_group(name, mount_point=mount_point)

    def create_or_update_user(
        self, username, policies=None, groups=None, mount_point=DEFAULT_MOUNT_POINT
    ):
        """
        Create or update LDAP users policies and group associations.

        Supported methods:
            POST: /auth/{mount_point}/users/{username}. Produces: 204 (empty body)


        :param username: The username of the LDAP user
        :type username: str | unicode
        :param policies: List of policies associated with the user. This parameter is transformed to a comma-delimited
            string before being passed to Vault.
        :type policies: str | unicode
        :param groups: List of groups associated with the user. This parameter is transformed to a comma-delimited
            string before being passed to Vault.
        :type groups: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_or_update_user request.
        :rtype: requests.Response
        """
        return super().create_or_update_user(username, policies=None, groups=None, mount_point=mount_point)

    def list_users(self, mount_point=DEFAULT_MOUNT_POINT):
        """
        List existing users in the method.

        Supported methods:
            LIST: /auth/{mount_point}/users. Produces: 200 application/json


        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the list_users request.
        :rtype: dict
        """
        return super().list_users(mount_point=DEFAULT_MOUNT_POINT)

    def read_user(self, username, mount_point=DEFAULT_MOUNT_POINT):
        """
        Read policies associated with a LDAP user.

        Supported methods:
            GET: /auth/{mount_point}/users/{username}. Produces: 200 application/json


        :param username: The username of the LDAP user
        :type username: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the read_user request.
        :rtype: dict
        """
        return super().read_user(username, mount_point=DEFAULT_MOUNT_POINT)

    def delete_user(self, username, mount_point=DEFAULT_MOUNT_POINT):
        """
        Delete a LDAP user and policy association.

        Supported methods:
            DELETE: /auth/{mount_point}/users/{username}. Produces: 204 (empty body)


        :param username: The username of the LDAP user
        :type username: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_user request.
        :rtype: requests.Response
        """
        return super().delete_user(username, mount_point=DEFAULT_MOUNT_POINT)

    def login(self,
              username,
              service=None,
              realm=None,
              keytab_path=None,
              krb5conf_path=None,
              use_token=True,
              mount_point=DEFAULT_MOUNT_POINT):
        """
        Login with KERBEROS credentials.

        This is the equivalent of the vault cli login command::

            vault login -method=kerberos \
                username=grace \
                service=HTTP/my-service \
                realm=MATRIX.LAN \
                keytab_path=/etc/krb5/krb5.keytab  \
                krb5conf_path=/etc/krb5.conf \
                disable_fast_negotiation=false

        Supported methods:
            ``POST: /auth/{mount_point}/login/{username}. Produces: 200 application/json``

        see: https://github.com/pythongssapi/requests-gssapi/blob/main/requests_gssapi/gssapi_.py#L146
            (how kerberos auth is implemented in Python)

        To further debug authentication issues, enable debbugging:
        - `logging.getLogger('requests_gssapi.gssapi_').setLevel(logging.DEBUG)`
        - `logging.getLogger('requests_gssapi.gssapi').setLevel(logging.DEBUG)`

        (This feature - SPNEGO auth - is supported by the vault kerberos HTTP api)
        see: https://www.vaultproject.io/api/auth/kerberos#login-with-kerberos

        **Example Exceptions**
        requests_gssapi.exceptions.SPNEGOExchangeError: stepping context failed: Major (851968): Unspecified GSS
        failure.  Minor code may provide more information, Minor (100005): Cannot find KDC for realm "EXAMPLE.COM"

        requests_gssapi.exceptions.SPNEGOExchangeError: stepping context failed: Major (851968): Unspecified GSS
        failure.  Minor code may provide more information, Minor (100005): Server
        vault/domain.example.com@DOMAIN.EXAMPLE.COM not found in Kerberos database

        If you get either of the above errors, and know your server-side principal exactly you will need to
        define the "service" argument above explicitly using the gssapi library

        If your Keyab is expired or has been changed
        gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (2529638930): Client's credentials have been revoked

        Your kerberos credential cache is authenticated with a different principal, or is corrupted
        gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (39756032): Principal in credential cache does not match desired name



        :param username: principal name to authenticate as, can contain @DOMAIN suffix for explicit REALM,
                         realm is optional. eg: "user@DOMAIN.COM", or just... "user".
                         If realm is given, the `realm` argument below becomes redundant.
        :param service: service principal can `gssapi.Name()` object or a String
                        The service can be a host-based service, for this purpose use the `/_HOST` suffix
        :param realm: (optional) the Kerberos realm
        :param keytab_path: (optional) Keytab file path
        :param krb5conf_path: (optional) explicit krb5.conf path, default paths on your platform.
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the :py:meth:`hvac.adapters.Adapter` instance under the _adapter Client attribute.
        :type use_token: bool
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the login_with_user request.
        :rtype: requests.Response
        """

        log = logging.getLogger(self.__class__.__name__)
        # suppress noisy modules
        gssapi_log = logging.getLogger("requests_gssapi.gssapi_")
        if gssapi_log.getEffectiveLevel() == logging.NOTSET:
            gssapi_log.setLevel(logging.CRITICAL)

        try:
            vault_host = urlparse(self._adapter.base_uri).netloc.split(':')[0]
        except Exception:
            log.error(f'unable to parse Vault url: {self._adapter.base_uri}')
            vault_host = ''

        # if realm is provided, and username is not a SPN, make it fully qualified
        if '@' not in username and realm:
            username = f'{username}@{realm}'

        # handle the likely meanings of the service name that was provided.
        # we explicitly convert "service" into a gssapi.Name() - this prevents gssapi from attempting to guess
        # various and illogical combinations of default-realm and service-name, avoiding dubious and confusing errors.
        # Instead, we try the logical combinations, this makes errors and what was attempted more transparent to
        # the user.
        if isinstance(service, str):
            service_name = service
            service_names = []
            # handle logic for the user to specify a service of "name/host"
            if '/' in service and '@' in service:
                # you can't do this....
                suffix = service.rsplit('@')[-1]
                raise ValueError(f'kerberos service="{service}" is invalid \nA host-based service cannot contain a '
                                 f'[@] realm qualifier.\nYou should remove the suffix: "@{suffix}"\n... or remove the '
                                 f'[/] (forward slash) host-based service qualifier')
            if '/' + HOST_TEMPLATE in service:
                # this is a host-based service with a _HOST template in it.
                service = service.replace('/' + HOST_TEMPLATE, '@' + vault_host)
                log.debug(f'translate "service" from "{service_name}" to "{service}" - host-based-service is assumed')
                service_names.append(gssapi.Name(service, gssapi.NameType.hostbased_service))
            elif '/' in service:
                # if "/" appears by itself convert it to a "@" - which is required by gssapi
                service = service.replace('/', '@')
                log.debug(f'translate "service" from "{service_name}" to "{service}" - host-based-service is assumed')
                service_names.append(gssapi.Name(service, gssapi.NameType.hostbased_service))
            elif '@' in service:
                # it may be a host-based or a principal service being defined
                # although we don't want people specifying a host-based-service in this manner, allow it
                log.debug('@ qualifier used for "service" - usually this means the user is specifying a principal name '
                          'for the service. We will try to authenticate both as a UPN and host-based-service')
                service_names.append(gssapi.Name(service, gssapi.NameType.kerberos_principal))
                service_names.append(gssapi.Name(service, gssapi.NameType.hostbased_service))
            elif '@' not in service and realm:
                # no realm qualifier or host qualifier was given...
                # it maybe a host-based or a principal service being defined, most likely a principal though
                log.debug('"service" has no realm qualifier [@] or host-based-service qualifier [/] \nUsually'
                          'this means the service being authenticated to is a principal (UPN). \nWe will attempt '
                          f'both a upn and a host-based-service. \nThe realm ({realm}) will be assumed for the UPN')
                service_names.append(gssapi.Name(f'{service}@{realm}', gssapi.NameType.kerberos_principal))
                service_names.append(gssapi.Name(f'{service}@{vault_host}', gssapi.NameType.hostbased_service))
            else:
                log.debug('"service" has no realm qualifier [@] or host-based-service qualifier [/], \nUsually '
                          'this means the service being authenticated to is a principal (UPN). \nWe will attempt '
                          'both a upn and a host-based-service.')
                service_names.append(gssapi.Name(service, gssapi.NameType.kerberos_principal))
                service_names.append(gssapi.Name(f'{service}@{vault_host}', gssapi.NameType.hostbased_service))
        elif isinstance(service, gssapi.Name):
            # if the user gave us a gssapi.Name() object then use that.
            service_name = gssapi_raw.display_name(service).name.decode()
            log.debug(f'"service" gssapi.Name() object provided - will be used as-is: "{service_name}"')
            service_names = [service]
        else:
            raise ValueError(f'service must be `str` or `gssapi.Name()`, got: {type(service)}')

        # KerberosContext will (if given) authenticate with kerberos via Keytab provided
        # this will generate a ticket getting ticket (tgt) and store it in the default ticket cache location

        if krb5conf_path:
            os.environ[ENV_KRB5_CONF] = krb5conf_path

        # Create a principal name object for gssapi
        gssapi_principal = gssapi.names.Name(username, gssapi.names.NameType.kerberos_principal)

        if keytab_path:
            # This means the user wishes to authenticate via Keytab
            # Keytabs are encrypted binary files that contain a tokenized version of the users password.
            # Each user may only have 1 valid keytab, if a new keytab is issued our their password is changed
            # any existing keytab is invalidated.

            # By default gssapi will look for an existing credentials cache unconditionally.
            # If gssapi finds an existing cache, it will ignore your keytab, and principal and raise an exception like:
            #
            #     gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.
            #     Minor code may provide more information, Minor (39756032): Principal in credential cache does not match desired name
            #
            #     SPNEGOExchangeError: stepping context failed: Major (851968): Unspecified GSS failure.
            #     Minor code may provide more information, Minor (100005): Ticket expired, on None None
            #
            # To avoid this, we trick gssapi, by temporarily giving an invalid cache location.


            if not isfile(keytab_path):
                raise KerberosError(f'keytab_path not a file: "{keytab_path}"\nIf you do not wish to use a keytab '
                                    f'for kerberos authentication, `keytab_path` must be set to None')
            try:
                open(keytab_path, 'rb').read(1)
            except IOError as e:
                raise KerberosError(f'the keytab at "{keytab_path}" could not be read - {e}')

            # temporarily remove the kerberos credentials cache from the environment variables.
            # we want to perform a NEW authentication nomatter what.
            restore = os.environ.get(ENV_KRB5_CACHE)
            fake_file = ''.join(random.choice(string.ascii_lowercase) for _ in range(20))
            ccache_file = f'FILE:/tmp/{fake_file}'
            os.environ[ENV_KRB5_CACHE] = ccache_file

            try:
                # specify non-existant cache to avoid
                # gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.
                #   Minor code may provide more information, Minor (2529639053):
                #       Can't find client principal upn@EXAMPLE.COM in cache collection
                gssapi_store = {'client_keytab': keytab_path}
                gssapi_creds = gssapi.creds.Credentials(usage='initiate',
                                                        name=gssapi_principal,
                                                        store=gssapi_store)
            except GSSError as e:
                # Can't find client principal vault-upn@DOMAIN.COM in cache collection
                if fnmatch.fnmatch(str(e), "* Can't find client principal * in cache collection*"):
                    raise KerberosError(f'The {GSSError.__name__} above was likely caused by the wrong or invalid '
                                        f'keytab being provided to gssapi.Credentials()...\n'
                                        f'Ensure the keytab: "{keytab_path}" contains the principal: '
                                        f'"{username}".\n'
                                        f'We show this exception in place of the original as the original is '
                                        f'misleading.\n'
                                        f'See the parent exception for more information.') from e
                raise
            finally:
                os.environ[ENV_KRB5_CACHE] = restore or ''

        else:
            # Find existing credentials from cache (there may be none)
            gssapi_creds = gssapi.creds.Credentials(usage='initiate',
                                                    name=gssapi_principal)

        # we know we want to use SPNEGO, do not allow any other form of authentication to be tried.
        # if we allow alternative forms, we will further complicate an administrators task of debugging failed auth
        # and cause excessive logging.
        try:
            spnego = gssapi.mechs.Mechanism.from_sasl_name("SPNEGO")
        except AttributeError:
            spnego = gssapi.OID.from_int_seq(SPNEGO_OID)

        # Kerberos login uri
        api_path = utils.format_url(
            '/v1/auth/{mount_point}/login',
            mount_point=mount_point,
        )

        try:
            svc_names_desc = '\n'.join([repr(n) for n in service_names if not isinstance(n, str)])
        except Exception as e:
            svc_names_desc = str(service_names)

        for count, name in enumerate(service_names, start=1):
            log.debug(f'Vault KerberosAuth attempt #{count}, principal: {username}, service:{name}, '
                      f'using keytab: {bool(keytab_path)} to {api_path}')
            try:
                # Spengo can perform multiple round-trips in negotiation... usually this is not needed
                # and the kerberos auth token can be granted on the first request, this is how most KDC's work.
                # for this reason we by default enable `opportunistic_auth`.
                auth = HTTPSPNEGOAuth(opportunistic_auth=True, mech=spnego, target_name=name, creds=gssapi_creds)

                # auth=HTTPSPNEGOAuth() will be passed as an argument to requests.
                # this argument sets the `Authorization: Negotiate` header needed by SPNEGO (kerberos over HTTP)
                # the SPNEGO token is generated by kerberos libraries used by `requests_gssapi`
                # Note that the SPNEGO token is resolved by negotiating the kerberos token against ``service``
                # requests.request('post', self.url.geturl(), **requestArgs)
                # Note: - when the service is explicitly defined, you may get no error but is_authenticated()
                #         will return false
                return self._adapter.login(
                    url=api_path,
                    use_token=use_token,
                    auth=auth  # sets SPNEGO "Authorization" header
                )
            except (GSSError, SPNEGOExchangeError) as e:
                # if we've exhausted the different ways to define "service" raise an error
                if count >= len(service_names):

                    raise Unauthorized('Kerberos authentication failed, we tried these kerberos service accounts:\n'
                                       f'{svc_names_desc}\n'
                                       f'The user value service-name passed: {service_name}\n'
                                       f'The underlying authentication mechanism (GSSAPI) failed to validate '
                                       f'the local kerberos token.\n{e.__class__.__name__}: {str(e)}') from e
                continue
            except Unauthorized as e:
                raise Unauthorized('Kerberos authentication failed\n'
                                   'we tried these kerberos service accounts:\n'
                                   f'{svc_names_desc}\n'
                                   'an [Unauthorized] error '
                                   'response from the server can mean you are using the wrong '
                                   'server-side principal, or the "service" argument does '
                                   'not match the Vault servers `service_name` setting. \n'
                                   'This error can also happen if your service principal does not '
                                   'contain the host-name the client is sending the request to.\n'
                                   f'service: {service_name}\n',
                                   errors=e.errors,
                                   method=e.method,
                                   url=e.url) from e

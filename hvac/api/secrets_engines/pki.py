#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Transit methods module."""
# from hvac import exceptions
from hvac.api.vault_api_base import VaultApiBase
# from hvac.constants import transit as transit_constants

DEFAULT_MOUNT_POINT = 'pki'


class Pki(VaultApiBase):
    """Pki Secrets Engine (API).

    Reference: https://www.vaultproject.io/api/secret/pki/index.html
    """

    # Read CA Certificate
    def read_ca_certificate(self, mount_point=DEFAULT_MOUNT_POINT):
        """Read CA Certificate.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The certificate as pem.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/ca/pem'.format(mount_point=mount_point)
        response = self._adapter.get(
            url=api_path,
        )
        return response.text

    # Read CA Certificate Chain
    def read_ca_certificate_chain(self, mount_point=DEFAULT_MOUNT_POINT):
        """Read CA Certificate Chain.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The certificate chain as pem.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/ca_chain'.format(mount_point=mount_point)
        response = self._adapter.get(
            url=api_path,
        )
        return response.text

    # Read Certificate
    def read_certificate(self, serial, mount_point=DEFAULT_MOUNT_POINT):
        """Read Certificate.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/cert/{serial}'.format(
            mount_point=mount_point,
            serial=serial,
        )
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    # List Certificates
    def list_certificates(self, mount_point=DEFAULT_MOUNT_POINT):
        """List Certificates.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/certs'.format(mount_point=mount_point)
        response = self._adapter.list(
            url=api_path,
        )
        return response.json()

    # Submit CA Information
    def submit_ca_information(self, params, mount_point=DEFAULT_MOUNT_POINT):
        """Submit CA Information.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/config/ca'.format(mount_point=mount_point)
        response = self._adapter.post(
            url=api_path,
            json=params,
        )
        return response

    # Read CRL Configuration
    def read_crl_configuration(self, mount_point=DEFAULT_MOUNT_POINT):
        """Read CRL Configuration.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/config/crl'.format(mount_point=mount_point)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    # Set CRL Configuration
    def set_crl_configuration(self, params, mount_point=DEFAULT_MOUNT_POINT):
        """Set CRL Configuration.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/config/crl'.format(mount_point=mount_point)
        response = self._adapter.post(
            url=api_path,
            json=params,
        )
        return response

    # Read URLs
    def read_urls(self, mount_point=DEFAULT_MOUNT_POINT):
        """Read URLs.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/config/urls'.format(mount_point=mount_point)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    # Set URLs
    def set_urls(self, params, mount_point=DEFAULT_MOUNT_POINT):
        """Set URLs.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/config/urls'.format(mount_point=mount_point)
        response = self._adapter.post(
            url=api_path,
            json=params,
        )
        return response

    # Read CRL
    def read_crl(self, mount_point=DEFAULT_MOUNT_POINT):
        """Read CRL.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/config/crl'.format(mount_point=mount_point)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    # Rotate CRLs
    def rotate_crl(self, mount_point=DEFAULT_MOUNT_POINT):
        """Rotate CRLs.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/crl/rotate'.format(mount_point=mount_point)
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    # Generate Intermediate
    def generate_intermediate(self, type, common_name, extra_params={}, mount_point=DEFAULT_MOUNT_POINT):
        """Generate Intermediate.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/intermediate/generate/{type}'.format(
            mount_point=mount_point,
            type=type,
        )

        params = extra_params
        params['common_name'] = common_name

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Set Signed Intermediate
    def set_signed_intermediate(self, certificate, mount_point=DEFAULT_MOUNT_POINT):
        """Generate Intermediate.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/intermediate/set-signed'.format(
            mount_point=mount_point,
        )

        params = {}
        params['certificate'] = certificate

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Generate Certificate
    def generate_certificate(self, name, common_name, extra_params={}, mount_point=DEFAULT_MOUNT_POINT):
        """Generate Certificate.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :name mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/issue/{name}'.format(
            mount_point=mount_point,
            name=name,
        )

        params = extra_params
        params['common_name'] = common_name

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Revoke Certificate
    def revoke_certificate(self, serial_number, mount_point=DEFAULT_MOUNT_POINT):
        """Revoke Certificate.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :name mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/revoke'.format(mount_point=mount_point)

        params = {}
        params['serial_number'] = serial_number

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Create/Update Role
    def create_or_update_role(self, name, extra_params={}, mount_point=DEFAULT_MOUNT_POINT):
        """Create/Update Role.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :name mount_point: str | unicode
        :return: The JSON response of the request.
        :rname: requests.Response
        """
        api_path = '/v1/{mount_point}/roles/{name}'.format(
            mount_point=mount_point,
            name=name,
        )

        params = extra_params
        params['name'] = name

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Read Role
    def read_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Read Role.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/roles/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        response = self._adapter.get(
            url=api_path,
        )
        return response.json()

    # List Roles
    def list_roles(self, mount_point=DEFAULT_MOUNT_POINT):
        """List Roles.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/roles'.format(mount_point=mount_point)
        response = self._adapter.list(
            url=api_path,
        )
        return response.json()

    # Delete Role
    def delete_role(self, name, extra_params={}, mount_point=DEFAULT_MOUNT_POINT):
        """Delete Role.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :name mount_point: str | unicode
        :return: The JSON response of the request.
        :rname: requests.Response
        """
        api_path = '/v1/{mount_point}/roles/{name}'.format(
            mount_point=mount_point,
            name=name,
        )

        return self._adapter.delete(
            url=api_path,
        )

    # Generate Root
    def generate_root(self, type, common_name, extra_params={}, mount_point=DEFAULT_MOUNT_POINT):
        """Generate Root.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/root/generate/{type}'.format(
            mount_point=mount_point,
            type=type,
        )

        params = extra_params
        params['common_name'] = common_name

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Delete Root
    def delete_root(self, mount_point=DEFAULT_MOUNT_POINT):
        """Delete Root.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/root'.format(
            mount_point=mount_point,
            type=type,
        )

        return self._adapter.delete(
            url=api_path,
        )

    # Sign Intermediate
    def sign_intermediate(self, csr, common_name, extra_params={}, mount_point=DEFAULT_MOUNT_POINT):
        """Sign Intermediate.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/root/sign-intermediate'.format(mount_point=mount_point)

        params = extra_params
        params['csr'] = csr
        params['common_name'] = common_name

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Sign Self-Issued
    def sign_self_issued(self, certificate, mount_point=DEFAULT_MOUNT_POINT):
        """Sign Self-Issued.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/root/sign-self-issued'.format(mount_point=mount_point)

        params = {}
        params['certificate'] = certificate

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Sign Certificate
    def sign_certificate(self, name, csr, common_name, extra_params={}, mount_point=DEFAULT_MOUNT_POINT):
        """Sign Certificate.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/sign/{name}'.format(
                mount_point=mount_point,
                name=name,
                )

        params = extra_params
        params['csr'] = csr
        params['common_name'] = common_name

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Sign Verbatim
    def sign_verbatim(self, csr, name=False, extra_params={}, mount_point=DEFAULT_MOUNT_POINT):
        """Sign Verbatim.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        if name:
            url_to_transform = '/v1/{mount_point}/sign-verbatim/{name}'
        else:
            url_to_transform = '/v1/{mount_point}/sign-verbatim'

        api_path = url_to_transform.format(
                mount_point=mount_point,
                name=name,
                )

        params = extra_params
        params['csr'] = csr

        return self._adapter.post(
            url=api_path,
            json=params,
        )

    # Tidy
    def tidy(self, extra_params={}, mount_point=DEFAULT_MOUNT_POINT):
        """Tidy.

        Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/tidy'.format(
                mount_point=mount_point,
                )

        params = extra_params

        return self._adapter.post(
            url=api_path,
            json=params,
        )

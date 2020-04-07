#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Transform secrets engine methods module."""
from hvac import utils
from hvac.api.vault_api_base import VaultApiBase

DEFAULT_MOUNT_POINT = 'transform'


class Transform(VaultApiBase):
    """Transform Secrets Engine (API).

    Reference: https://www.vaultproject.io/api-docs/secret/transform
    """

    def create_or_update_role(self, name, transformations, mount_point=DEFAULT_MOUNT_POINT):
        """Creates or update the role with the given name.

        If a role with the name does not exist, it will be created. If the role exists, it will be
        updated with the new attributes.

        Supported methods:
            POST: /{mount_point}/role/:name.

        :param name: the name of the role to create. This is part of the request URL.
        :type name: str | unicode
        :param transformations: Specifies the transformations that can be used with this role.
            At least one transformation is required.
        :type transformations: list
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_or_update_role request.
        :rtype: requests.Response
        """
        params = {
            'transformations': transformations,
        }
        api_path = '/v1/{mount_point}/role/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Query an existing role by the given name.

        Supported methods:
            GET: /{mount_point}/role/:name.

        :param name: the name of the role to read. This is part of the request URL.
        :type name: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_role request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/role/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.get(
            url=api_path,
        )

    def list_roles(self, mount_point=DEFAULT_MOUNT_POINT):
        """List all existing roles in the secrets engine.

        Supported methods:
            LIST: /{mount_point}/role.

        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the list_roles request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/role'.format(mount_point=mount_point)
        return self._adapter.list(
            url=api_path,
        )

    def delete_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Delete an existing role by the given name.

        Supported methods:
            DELETE: /{mount_point}/role/:name.

        :param name: the name of the role to delete. This is part of the request URL.
        :type name: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_role request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/role/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.delete(
            url=api_path,
        )

    def create_or_update_transformation(self, name, transform_type, template, tweak_source="supplied",
                                        masking_character="*", allowed_roles=None, mount_point=DEFAULT_MOUNT_POINT):
        """Create or update a transformation with the given name.

        If a transformation with the name does not exist, it will be created. If the
        transformation exists, it will be updated with the new attributes.

        Supported methods:
            POST: /{mount_point}/transformation/:name.

        :param name: the name of the transformation to create or update. This is part of
            the request URL.
        :type name: str | unicode
        :param transform_type: Specifies the type of transformation to perform.
            The types currently supported by this backend are fpe and masking.
            This value cannot be modified by an update operation after creation.
        :type transform_type: str | unicode
        :param template: the template name to use for matching value on encode and decode
            operations when using this transformation.
        :type template: str | unicode
        :param tweak_source: Only used when the type is FPE.
        :type tweak_source: str | unicode
        :param masking_character: the character to use for masking. If multiple characters are
            provided, only the first one is used and the rest is ignored. Only used when
            the type is masking.
        :type masking_character: str | unicode
        :param allowed_roles: a list of allowed roles that this transformation can be assigned to.
            A role using this transformation must exist in this list in order for
            encode and decode operations to properly function.
        :type allowed_roles: list
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_or_update_ation request.
        :rtype: requests.Response
        """
        params = {
            'type': transform_type,
            'template': template,
            'tweak_source': tweak_source,
            'masking_character': masking_character,
        }
        params.update(utils.remove_nones({
            'allowed_roles': allowed_roles,
        }))
        api_path = '/v1/{mount_point}/transformation/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_transformation(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Query an existing transformation by the given name.

        Supported methods:
            GET: /{mount_point}/transformation/:name.

        :param name: Specifies the name of the role to read.
        :type name: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_ation request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/transformation/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.get(
            url=api_path,
        )

    def list_transformations(self, mount_point=DEFAULT_MOUNT_POINT):
        """List all existing transformations in the secrets engine.

        Supported methods:
            LIST: /{mount_point}/transformation.

        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the list_ation request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/transformation'.format(mount_point=mount_point)
        return self._adapter.list(
            url=api_path,
        )

    def delete_transformation(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Delete an existing transformation by the given name.

        Supported methods:
            DELETE: /{mount_point}/transformation/:name.

        :param name: the name of the transformation to delete. This is part of the
            request URL.
        :type name: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_ation request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/transformation/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.delete(
            url=api_path,
        )

    def create_or_update_template(self, name, template_type, pattern, alphabet, mount_point=DEFAULT_MOUNT_POINT):
        """Creates or update a template with the given name.

        If a template with the name does not exist, it will be created. If the
        template exists, it will be updated with the new attributes.

        Supported methods:
            POST: /{mount_point}/template/:name.

        :param name: the name of the template to create.
        :type name: str | unicode
        :param template_type: Specifies the type of pattern matching to perform.
            The ony type currently supported by this backend is regex.
        :type template_type: str | unicode
        :param pattern: the pattern used to match a particular value. For regex type
            matching, capture group determines the set of character that should be matched
            against. Any matches outside of capture groups are retained
            post-transformation.
        :type pattern: str | unicode
        :param alphabet: the name of the alphabet to use when this template is used for FPE
            encoding and decoding operations.
        :type alphabet: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_or_update_template request.
        :rtype: requests.Response
        """
        params = {
            'type': template_type,
            'pattern': pattern,
            'alphabet': alphabet,
        }
        api_path = '/v1/{mount_point}/template/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_template(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Query an existing template by the given name.

        Supported methods:
            GET: /{mount_point}/template/:name.

        :param name: Specifies the name of the role to read.
        :type name: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_template request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/template/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.get(
            url=api_path,
        )

    def list_templates(self, mount_point=DEFAULT_MOUNT_POINT):
        """List all existing templates in the secrets engine.

        Supported methods:
            LIST: /{mount_point}/transformation.

        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the list_template request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/template'.format(mount_point=mount_point)
        return self._adapter.list(
            url=api_path,
        )

    def delete_template(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Delete an existing template by the given name.

        Supported methods:
            DELETE: /{mount_point}/template/:name.

        :param name: the name of the template to delete. This is part of the
            request URL.
        :type name: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_template request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
        }
        api_path = '/v1/{mount_point}/template/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.delete(
            url=api_path,
            json=params,
        )

    def create_or_update_alphabet(self, name, alphabet, mount_point=DEFAULT_MOUNT_POINT):
        """Create or update an alphabet with the given name.

        If an alphabet with the name does not exist, it will be created. If the
        alphabet exists, it will be updated with the new attributes.

        Supported methods:
            POST: /{mount_point}/alphabet/:name.

        :param name: Specifies the name of the transformation alphabet to create.
        :type name: str | unicode
        :param alphabet: the set of characters that can exist within the provided value
            and the encoded or decoded value for a FPE transformation.
        :type alphabet: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_or_update_alphabet request.
        :rtype: requests.Response
        """
        params = {
            'alphabet': alphabet,
        }
        api_path = '/v1/{mount_point}/alphabet/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_alphabet(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Queries an existing alphabet by the given name.

        Supported methods:
            GET: /{mount_point}/alphabet/:name.


        :param name: the name of the alphabet to delete. This is part of the request URL.
        :type name: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_alphabet request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/alphabet/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.get(
            url=api_path,
        )

    def list_alphabets(self, mount_point=DEFAULT_MOUNT_POINT):
        """List all existing alphabets in the secrets engine.

        Supported methods:
            LIST: /{mount_point}/alphabet.

        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the list_alphabets request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/alphabet'.format(mount_point=mount_point)
        return self._adapter.list(
            url=api_path,
        )

    def delete_alphabet(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Delete an existing alphabet by the given name.

        Supported methods:
            DELETE: /{mount_point}/alphabet/:name.

        :param name: the name of the alphabet to delete. This is part of the request URL.
        :type name: str | unicode
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_alphabet request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/alphabet/{name}'.format(
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.delete(
            url=api_path,
        )

    def encode(self, role_name, value=None, transformation=None, tweak=None, batch_input=None, mount_point=DEFAULT_MOUNT_POINT):
        """Encode the provided value using a named role.

        Supported methods:
            POST: /{mount_point}/encode/:role_name.

        :param role_name: the role name to use for this operation. This is specified as part
            of the URL.
        :type role_name: str | unicode
        :param value: the value to be encoded.
        :type value: str | unicode
        :param transformation: the transformation within the role that should be used for this
            encode operation. If a single transformation exists for role, this parameter
            may be skipped and will be inferred. If multiple transformations exist, one
            must be specified.
        :type transformation: str | unicode
        :param tweak: the tweak source.
        :type tweak: str | unicode
        :param batch_input: a list of items to be encoded in a single batch. When this
            parameter is set, the 'value', 'transformation' and 'tweak' parameters are
            ignored. Instead, the aforementioned parameters should be provided within
            each object in the list.
        :type batch_input: list
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the encode request.
        :rtype: requests.Response
        """
        params = utils.remove_nones({
            'value': value,
            'transformation': transformation,
            'tweak': tweak,
            'batch_input': batch_input,
        })
        api_path = '/v1/{mount_point}/encode/{role_name}'.format(
            mount_point=mount_point,
            role_name=role_name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def decode(self, role_name, value=None, transformation=None, tweak=None, batch_input=None, mount_point=DEFAULT_MOUNT_POINT):
        """Decode the provided value using a named role.

        Supported methods:
            POST: /{mount_point}/decode/:role_name.

        :param role_name: the role name to use for this operation. This is specified as part
            of the URL.
        :type role_name: str | unicode
        :param value: the value to be decoded.
        :type value: str | unicode
        :param transformation: the transformation within the role that should be used for this
            decode operation. If a single transformation exists for role, this parameter
            may be skipped and will be inferred. If multiple transformations exist, one
            must be specified.
        :type transformation: str | unicode
        :param tweak: the tweak source.
        :type tweak: str | unicode
        :param batch_input: a list of items to be decoded in a single batch. When this
            parameter is set, the 'value', 'transformation' and 'tweak' parameters are
            ignored. Instead, the aforementioned parameters should be provided within
            each object in the list.
        :type batch_input: array<object>
        :param mount_point: The "path" the secrets engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the decode request.
        :rtype: requests.Response
        """
        params = utils.remove_nones({
            'value': value,
            'transformation': transformation,
            'tweak': tweak,
            'batch_input': batch_input,
        })
        api_path = '/v1/{mount_point}/decode/{role_name}'.format(
            mount_point=mount_point,
            role_name=role_name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

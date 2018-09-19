#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""KvV2 methods module."""
from hvac import exceptions
from hvac.api.vault_api_base import VaultApiBase

DEFAULT_MOUNT_POINT = 'identity'


class Identity(VaultApiBase):
    """Identity Secrets Engine (API).

    Reference: https://www.vaultproject.io/api/secret/identity/entity.html
    """

    def create_or_update_entity(self, name, id=None, metadata=None, policies=None, disabled=False, mount_point=DEFAULT_MOUNT_POINT):
        """Creates or updates an Entity.

        Supported methods:
            POST: /{mount_point}/entity. Produces: 200 (application/json)


        :param name: Name of the entity.
        :type name: str
        :param id: ID of the entity. If set, updates the corresponding existing entity.
        :type id: str
        :param metadata: Metadata to be associated with the entity.
        :type metadata: dict
        :param policies: Policies to be tied to the entity.
        :type policies: List[str]
        :param disabled: Whether the entity is disabled. Disabled entities' associated tokens cannot be used, but are not revoked.
        :type disabled: bool
        :param mount_point: The "path" the secret engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        params = {
            name,
            id,
            metadata,
            policies,
            disabled
        }
        api_path = '/v1/{mount_point}/entity'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_entity(self, id, mount_point=DEFAULT_MOUNT_POINT):
        """Queries the entity by its identifier.

        Supported methods:
            GET: /auth/{mount_point}/entity/id/{id}. Produces: 200 application/json

        :param id: Identifier of the entity.
        :type id: str
        :param mount_point: The "path" the secret engine was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = '/v1/{mount_point}//entity/id/{id}'.format(
            mount_point=mount_point,
            id=id
        )
        response = self._adapter.get(url=api_path)
        return response.json()

    def delete_entity(self, id, mount_point=DEFAULT_MOUNT_POINT):
        """Issue a soft delete of the secret's latest version at the specified location.

        This marks the version as deleted and will stop it from being returned from reads, but the underlying data will
        not be removed. A delete can be undone using the undelete path.

        Supported methods:
            DELETE: /{mount_point}/entity/id/{id}. Produces: 204 (empty body)


        :param id: Identifier of the entity.
        :type id: str
        :param mount_point: The "path" the secret engine was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/entity/id/{id}'.format(mount_point=mount_point, id=id)
        return self._adapter.delete(
            url=api_path,
        )

    def list_entity_ids(self, mount_point=DEFAULT_MOUNT_POINT):
        """Returns a list of available entities by their identifiers.
        Supported methods:
            LIST: /{mount_point}/metadata/{path}. Produces: 200 application/json


        :param mount_point: The "path" the secret engine was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = '/v1/{mount_point}/entity/id'.format(mount_point=mount_point)
        response = self._adapter.list(
            url=api_path,
        )
        return response.json()

    def lookup_entity(self, name=None, id=None, alias_id=None, alias_name=None, alias_mount_accessor=None, mount_point=DEFAULT_MOUNT_POINT):
        """Queries the entity based on the given criteria. The criteria can be name, id, alias_id, or a combination of alias_name and alias_mount_accessor.
        Supported methods:
            POST: /v1/{mount_point}/lookup/entity. Produces: 200 application/json
        
        :param name: Name of the entity.
        :type name: str
        :param id: ID of the entity.
        :type id: str | unicode
        :param alias_id: ID of the alias.
        :type alias_id: str | unicode
        :param alias_name: Name of the alias. This should be supplied in conjunction with alias_mount_accessor.
        :type alias_name: str | unicode
        :param alias_mount_accessor: Accessor of the mount to which the alias belongs to. This should be supplied in conjunction with alias_name.
        :type alias_mount_accessor: str
        :param mount_point: The "path" the secret engine was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        params = { }

        if name is not None:
            params['name'] = name
        if id is not None:
            params['id'] = id
        if alias_id is not None:
            params['alias_id'] = alias_id
        if alias_name is not None:
            params['alias_name'] = alias_name
        if alias_mount_accessor is not None:
            params['alias_mount_accessor'] = alias_mount_accessor 

        api_path = '/v1/{mount_point}/lookup/entity'.format(mount_point=mount_point)
        response = self._adapter.post(
            url=api_path,
            json=params
        )
        return response.json()
Identity
========

.. versionadded:: Vault 0.9.0

.. contents::

Entity
------

Create Or Update Entity
```````````````````````

:py:meth:`hvac.api.secrets_engines.Identity.create_or_update_entity`

.. code:: python

	import hvac
	client = hvac.Client()

	create_response = client.secrets.identity.create_or_update_entity(
			name='hvac-entity',
			metadata=dict(extra_datas='yup'),
		)
	entity_id = create_response['data']['id']
	print('Entity ID for "hvac-entity" is: {id}'.format(id=entity_id))


Create Or Update Entity By Name
```````````````````````````````

:py:meth:`hvac.api.secrets_engines.Identity.create_or_update_entity_by_name`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.create_or_update_entity_by_name(
		name='hvac-entity',
		metadata=dict(new_datas='uhuh'),
	)


Read Entity
```````````

:py:meth:`hvac.api.secrets_engines.Identity.read_entity`

.. code:: python

	import hvac
	client = hvac.Client()

	read_response = client.secrets.identity.read_entity(
		entity_id=entity_id,
	)
	name = read_response['data']['name']
	print('Name for entity ID {id} is: {name}'.format(id=entity_id, name=name))


Read Entity By Name
```````````````````

.. versionadded:: Vault 0.11.2

:py:meth:`hvac.api.secrets_engines.Identity.read_entity_by_name`

.. code:: python

	import hvac
	client = hvac.Client()

	read_response = client.secrets.identity.read_entity_by_name(
		name='hvac-entity',
	)
	entity_id = read_response['data']['id']
	print('Entity ID for "hvac-entity" is: {id}'.format(id=entity_id))


Update Entity
`````````````

:py:meth:`hvac.api.secrets_engines.Identity.update_entity`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.update_entity(
		entity_id=entity_id,
		metadata=dict(new_metadata='yup'),
	)


Delete Entity
`````````````

:py:meth:`hvac.api.secrets_engines.Identity.delete_entity`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.delete_entity(
		entity_id=entity_id,
	)


Delete Entity By Name
`````````````````````

.. versionadded:: Vault 0.11.2

:py:meth:`hvac.api.secrets_engines.Identity.delete_entity_by_name`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.delete_entity_by_name(
		name='hvac-entity',
	)


List Entities
`````````````

:py:meth:`hvac.api.secrets_engines.Identity.list_entities`

.. code:: python

	import hvac
	client = hvac.Client()

	list_response = client.secrets.identity.list_entities()
	entity_keys = list_response['data']['keys']
	print('The following entity IDs are currently configured: {keys}'.format(keys=entity_keys))


List Entities By Name
`````````````````````

.. versionadded:: Vault 0.11.2

:py:meth:`hvac.api.secrets_engines.Identity.list_entities_by_name`

.. code:: python

	import hvac
	client = hvac.Client()

	list_response = client.secrets.identity.list_entities_by_name()
	entity_keys = list_response['data']['keys']
	print('The following entity names are currently configured: {keys}'.format(keys=entity_keys))


Merge Entities
``````````````

:py:meth:`hvac.api.secrets_engines.Identity.merge_entities`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.merge_entities(
		from_entity_ids=from_entity_ids,
		to_entity_id=to_entity_id,
	)

Entity Alias
------------

Create Or Update Entity Alias
`````````````````````````````

:py:meth:`hvac.api.secrets_engines.Identity.create_or_update_entity_alias`

.. code:: python

	import hvac
	client = hvac.Client()

	create_response = client.secrets.identity.create_or_update_entity_alias(
		name='hvac-entity-alias',
		canonical_id=entity_id,
		mount_accessor='auth_approle_73c16de3',
	)
	alias_id = create_response['data']['id']
	print('Alias ID for "hvac-entity-alias" is: {id}'.format(id=alias_id))


Read Entity Alias
`````````````````

:py:meth:`hvac.api.secrets_engines.Identity.read_entity_alias`

.. code:: python

	import hvac
	client = hvac.Client()

	read_response = client.secrets.identity.read_entity_alias(
		alias_id=alias_id,
	)
	name = read_response['data']['name']
	print('Name for entity alias {id} is: {name}'.format(id=alias_id, name=name))


Update Entity Alias
```````````````````

:py:meth:`hvac.api.secrets_engines.Identity.update_entity_alias`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.update_entity_alias(
		alias_id=alias_id,
		name='new-alias-name',
		canonical_id=entity_id,
		mount_accessor='auth_approle_73c16de3',
	)

List Entity Aliases
```````````````````

:py:meth:`hvac.api.secrets_engines.Identity.list_entity_aliases`

.. code:: python

	import hvac
	client = hvac.Client()

	list_response = client.secrets.identity.list_entity_aliases()
	alias_keys = list_response['data']['keys']
	print('The following entity alias IDs are currently configured: {keys}'.format(keys=alias_keys))


Delete Entity Alias
```````````````````

:py:meth:`hvac.api.secrets_engines.Identity.delete_entity_alias`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.delete_entity_alias(
		alias_id=alias_id,
	)

Group
-----

Create Or Update Group
``````````````````````

:py:meth:`hvac.api.secrets_engines.Identity.create_or_update_group`

.. code:: python

	import hvac
	client = hvac.Client()

	create_response = client.secrets.identity.create_or_update_group(
		name='hvac-group',
		metadata=dict(extra_datas='we gots em'),
	)
	group_id = create_response['data']['id']
	print('Group ID for "hvac-group" is: {id}'.format(id=group_id))


Read Group
``````````

:py:meth:`hvac.api.secrets_engines.Identity.read_group`

.. code:: python

	import hvac
	client = hvac.Client()

	read_response = client.secrets.identity.read_group(
		group_id=group_id,
	)
	name = read_response['data']['name']
	print('Name for group ID {id} is: {name}'.format(id=group_id, name=name))


Update Group
````````````

:py:meth:`hvac.api.secrets_engines.Identity.update_group`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.update_group(
		group_id=group_id,
		metadata=dict(new_metadata='yup'),
	)


Delete Group
````````````

:py:meth:`hvac.api.secrets_engines.Identity.delete_group`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.delete_group(
		group_id=group_id,
	)


List Groups
```````````

:py:meth:`hvac.api.secrets_engines.Identity.list_groups`

.. code:: python

	import hvac
	client = hvac.Client()

	list_response = client.secrets.identity.list_groups()
	group_keys = list_entities_response['data']['keys']
	print('The following group IDs are currently configured: {keys}'.format(keys=group_keys))


List Groups By Name
```````````````````

.. versionadded:: Vault 0.11.2

:py:meth:`hvac.api.secrets_engines.Identity.list_groups_by_name`

.. code:: python

	import hvac
	client = hvac.Client()

	list_response = client.secrets.identity.list_groups_by_name()
	group_keys = list_response['data']['keys']
	print('The following group names are currently configured: {keys}'.format(keys=group_keys))


Create Or Update Group By Name
``````````````````````````````

.. versionadded:: Vault 0.11.2

:py:meth:`hvac.api.secrets_engines.Identity.create_or_update_group_by_name`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.create_or_update_group_by_name(
		name='hvac-group',
		metadata=dict(new_datas='uhuh'),
	)


Read Group By Name
``````````````````

.. versionadded:: Vault 0.11.2

:py:meth:`hvac.api.secrets_engines.Identity.read_group_by_name`

.. code:: python

	import hvac
	client = hvac.Client()

	read_response = client.secrets.identity.read_group_by_name(
		name='hvac-group',
	)
	group_id = read_response['data']['id']
	print('Group ID for "hvac-group" is: {id}'.format(id=group_id))


Delete Group By Name
````````````````````

.. versionadded:: Vault 0.11.2

:py:meth:`hvac.api.secrets_engines.Identity.delete_group_by_name`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.delete_group_by_name(
		name='hvac-group',
	)

Group Alias
-----------

Create Or Update Group Alias
````````````````````````````

:py:meth:`hvac.api.secrets_engines.Identity.create_or_update_group_alias`

.. code:: python

	import hvac
	client = hvac.Client()

	create_response = client.secrets.identity.create_or_update_group_alias(
			name='hvac-group-alias',
			canonical_id=group_id,
			mount_accessor='auth_approle_73c16de3',
		)
	alias_id = create_response['data']['id']
	print('Group alias ID for "hvac-group_alias" is: {id}'.format(id=alias_id))


Update Group Alias
``````````````````

:py:meth:`hvac.api.secrets_engines.Identity.update_group_alias`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.update_group_alias(
		alias_id=alias_id,
		name='new-alias-name',
		canonical_id=group_id,
		mount_accessor='auth_approle_73c16de3',
	)


Read Group Alias
````````````````

:py:meth:`hvac.api.secrets_engines.Identity.read_group_alias`

.. code:: python

	import hvac
	client = hvac.Client()

	read_response = client.secrets.identity.read_group_alias(
		alias_id=alias_id,
	)
	name = read_response['data']['name']
	print('Name for group alias {id} is: {name}'.format(id=alias_id, name=name))


Delete Group Alias
``````````````````

:py:meth:`hvac.api.secrets_engines.Identity.delete_group_alias`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.identity.delete_group_alias(
		alias_id=alias_id,
	)


List Group Aliases
``````````````````

:py:meth:`hvac.api.secrets_engines.Identity.list_group_aliases`

.. code:: python

	import hvac
	client = hvac.Client()

	list_response = client.secrets.identity.list_group_aliases()
	alias_keys = list_response['data']['keys']
	print('The following group alias IDs are currently configured: {keys}'.format(keys=alias_keys))

Lookup
------

Lookup Entity
`````````````

:py:meth:`hvac.api.secrets_engines.Identity.lookup_entity`

.. code:: python

	import hvac
	client = hvac.Client()

	lookup_response = client.secrets.identity.lookup_entity(
		name='hvac-entity',
	)
	entity_id = lookup_response['data']['id']
	print('Entity ID for "hvac-entity" is: {id}'.format(id=entity_id))


Lookup Group
````````````

:py:meth:`hvac.api.secrets_engines.Identity.lookup_group`

.. code:: python

	import hvac
	client = hvac.Client()

	lookup_response = client.secrets.identity.lookup_group(
		name='hvac-group',
	)
	group_id = lookup_response['data']['id']
	print('Group ID for "hvac-entity" is: {id}'.format(id=group_id))



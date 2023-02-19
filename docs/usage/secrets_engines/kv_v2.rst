KV - Version 2
==============

.. note::
    Every method under the :py:attr:`Kv class's v2 attribute<hvac.api.secrets_engines.Kv>` includes a `mount_point` parameter that can be used to address the KvV2 secret engine under a custom mount path. E.g., If enabling the KvV2 secret engine using Vault's CLI commands via `vault secrets enable -path=my-kvv2 -version=2 kv`", the `mount_point` parameter in :py:meth:`hvac.api.secrets_engines.KvV2` methods would be set to "my-kvv2".

Configuration
-------------

:py:meth:`hvac.api.secrets_engines.KvV2.configure`

Setting the default `max_versions` for a key/value engine version 2 under a path of `kv`:

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.configure(
        max_versions=20,
        mount_point='kv',
    )

Setting the default `cas_required` (check-and-set required) flag under the implicit default path of `secret`:

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.configure(
        cas_required=True,
    )

Read Configuration
------------------

:py:meth:`hvac.api.secrets_engines.KvV2.configure`

Reading the configuration of a KV version 2 engine mounted under a path of `kv`:

.. code:: python

    import hvac
    client = hvac.Client()

    kv_configuration = client.secrets.kv.v2.read_configuration(
        mount_point='kv',
    )
    print('Config under path "kv": max_versions set to "{max_ver}"'.format(
        max_ver=kv_configuration['data']['max_versions'],
    ))
    print('Config under path "kv": check-and-set require flag set to {cas}'.format(
        cas=kv_configuration['data']['cas_required'],
    ))


Read Secret Versions
--------------------

:py:meth:`hvac.api.secrets_engines.KvV2.read_secret_version`

Read the latest version of a given secret/path ("hvac"):

.. code:: python

    import hvac
    client = hvac.Client()

    secret_version_response = client.secrets.kv.v2.read_secret_version(
        path='hvac',
    )
    print('Latest version of secret under path "hvac" contains the following keys: {data}'.format(
        data=secret_version_response['data']['data'].keys(),
    ))
    print('Latest version of secret under path "hvac" created at: {date}'.format(
        date=secret_version_response['data']['metadata']['created_time'],
    ))
    print('Latest version of secret under path "hvac" is version #{ver}'.format(
        ver=secret_version_response['data']['metadata']['version'],
    ))


Read specific version (1) of a given secret/path ("hvac"):

.. code:: python

    import hvac
    client = hvac.Client()

    secret_version_response = client.secrets.kv.v2.read_secret_version(
        path='hvac',
        version=1,
    )
    print('Version 1 of secret under path "hvac" contains the following keys: {data}'.format(
        data=secret_version_response['data']['data'].keys(),
    ))
    print('Version 1 of secret under path "hvac" created at: {date}'.format(
        date=secret_version_response['data']['metadata']['created_time'],
    ))



Create/Update Secret
--------------------

:py:meth:`hvac.api.secrets_engines.KvV2.create_or_update_secret`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.create_or_update_secret(
        path='hvac',
        secret=dict(pssst='this is secret'),
    )

`cas` parameter with an argument that doesn't match the current version:

.. code:: python

    import hvac
    client = hvac.Client()

    # Assuming a current version of "6" for the path "hvac" =>
    client.secrets.kv.v2.create_or_update_secret(
        path='hvac',
        secret=dict(pssst='this is secret'),
        cas=5,
    )  # Raises hvac.exceptions.InvalidRequest

`cas` parameter set to `0` will only succeed if the path hasn't already been written.

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.create_or_update_secret(
        path='hvac',
        secret=dict(pssst='this is secret #1'),
        cas=0,
    )

    client.secrets.kv.v2.create_or_update_secret(
        path='hvac',
        secret=dict(pssst='this is secret #2'),
        cas=0,
    )  # => Raises hvac.exceptions.InvalidRequest

Patch Existing Secret
---------------------

Method (similar to the Vault CLI command `vault kv patch`) to update an existing path. Either to add a new key/value to the secret and/or update the value for an existing key. Raises an :py:class:`hvac.exceptions.InvalidRequest` if the path hasn't been written to previously.

:py:meth:`hvac.api.secrets_engines.KvV2.patch`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.patch(
        path='hvac',
        secret=dict(pssst='this is a patched secret'),
    )


Delete Latest Version of Secret
-------------------------------

:py:meth:`hvac.api.secrets_engines.KvV2.delete_latest_version_of_secret`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.delete_latest_version_of_secret(
        path=hvac,
    )

Delete Secret Versions
----------------------

:py:meth:`hvac.api.secrets_engines.KvV2.delete_secret_versions`

Marking the first 3 versions of a secret deleted under path "hvac":

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.delete_secret_versions(
        path='hvac',
        versions=[1, 2, 3],
    )

Undelete Secret Versions
------------------------

:py:meth:`hvac.api.secrets_engines.KvV2.undelete_secret_versions`

Marking the last 3 versions of a secret deleted under path "hvac" as "undeleted":

.. code:: python

    import hvac
    client = hvac.Client()

    hvac_path_metadata = client.secrets.kv.v2.read_secret_metadata(
        path='hvac',
    )

    oldest_version = hvac_path_metadata['data']['oldest_version']
    current_version = hvac_path_metadata['data']['current_version']
    versions_to_undelete = range(max(oldest_version, current_version - 2), current_version + 1)

    client.secrets.kv.v2.undelete_secret_versions(
        path='hvac',
        versions=versions_to_undelete,
    )

Destroy Secret Versions
-----------------------

:py:meth:`hvac.api.secrets_engines.KvV2.destroy_secret_versions`

Destroying the first three versions of a secret under path 'hvac':

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.destroy_secret_versions(
        path='hvac',
        versions=[1, 2, 3],
    )

List Secrets
------------

:py:meth:`hvac.api.secrets_engines.KvV2.list_secrets`

Listing secrets under the 'hvac' path prefix:

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.create_or_update_secret(
        path='hvac/big-ole-secret',
        secret=dict(pssst='this is a large secret'),
    )

    client.secrets.kv.v2.create_or_update_secret(
        path='hvac/lil-secret',
        secret=dict(pssst='this secret... not so big'),
    )

    list_response = client.secrets.kv.v2.list_secrets(
        path='hvac',
    )

    print('The following paths are available under "hvac" prefix: {keys}'.format(
        keys=','.join(list_response['data']['keys']),
    ))


Read Secret Metadata
--------------------

:py:meth:`hvac.api.secrets_engines.KvV2.read_secret_metadata`

.. code:: python

    import hvac
    client = hvac.Client()

    hvac_path_metadata = client.secrets.kv.v2.read_secret_metadata(
        path='hvac',
    )

    print('Secret under path hvac is on version {cur_ver}, with an oldest version of {old_ver}'.format(
        cur_ver=hvac_path_metadata['data']['oldest_version'],
        old_ver=hvac_path_metadata['data']['current_version'],
    ))

Update Metadata
---------------

:py:meth:`hvac.api.secrets_engines.KvV2.update_metadata`

Set max versions for a given path ("hvac") to 3:

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.update_metadata(
        path='hvac',
        max_versions=3,
    )

Set cas (check-and-set) parameter as required for a given path ("hvac"):

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.update_metadata(
        path='hvac',
        cas_required=True,
    )

Set "delete_version_after" value to 30 minutes for all new versions written to the "hvac" path / key:

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.update_metadata(
        path='hvac',
        delete_version_after="30m",
    )

Describe the secret with custom metadata values in ``custom_metadata`` (Vault >= 1.9.0):

.. code:: python

    import hvac
    client = hvac.Client()

    clients.secrets.kv.v2.update_metadata(
        path='hvac',
        custom_metadata={
            "type": "api-token",
            "color": "blue",
        },
    )


Delete Metadata and All Versions
--------------------------------

:py:meth:`hvac.api.secrets_engines.KvV2.delete_metadata_and_all_versions`

Delete all versions and metadata for a given path:

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v2.delete_metadata_and_all_versions(
        path='hvac',
    )

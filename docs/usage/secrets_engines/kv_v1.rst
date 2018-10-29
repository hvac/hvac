KV - Version 1
==============

.. note::
    Every method under the :py:attr:`Kv class's v1 attribute<hvac.api.secrets_engines.Kv>` includes a `mount_point` parameter that can be used to address the KvV1 secret engine under a custom mount path. E.g., If enabling the KvV1 secret engine using Vault's CLI commands via `vault secrets enable -path=my-kvv1 -version=1 kv`", the `mount_point` parameter in :py:meth:`hvac.api.secrets_engines.KvV1` methods would be set to "my-kvv1".



Read a Secret
-------------

:py:meth:`hvac.api.secrets_engines.KvV1.read_secret`

.. code:: python

    import hvac
    client = hvac.Client()

    # The following path corresponds, when combined with the mount point, to a full Vault API route of "v1/secretz/hvac"
    mount_point = 'secretz'
    secret_path = 'hvac'

    read_secret_result = client.secrets.kv.v1.read_secret(
        path=secret_path,
        mount_point=mount_point,
    )
    print('The "psst" key under the secret path ("/v1/secret/hvac") is: {psst}'.format(
        psst=read_secret_result['data']['psst'],
    ))

List Secrets
------------

:py:meth:`hvac.api.secrets_engines.KvV1.list_secrets`

.. code:: python

    import hvac
    client = hvac.Client()

    list_secrets_result = client.secrets.kv.v1.list_secrets(path='hvac')

    print('The following keys found under the selected path ("/v1/secret/hvac"): {keys}'.format(
        keys=','.join(list_secrets_result['data']['keys']),
    ))

Create or Update a Secret
-------------------------

:py:meth:`hvac.api.secrets_engines.KvV1.create_or_update_secret`

.. code:: python

    import hvac
    client = hvac.Client()
    hvac_secret = {
        'psst': 'this is so secret yall',
    }

    client.secrets.kv.v1.create_or_update_secret(
        path='hvac',
        secret=hvac_secret,
    )

    read_secret_result = client.secrets.kv.v1.read_secret(
        path='hvac',
    )
    print('The "psst" key under the secret path ("/v1/secret/hvac") is: {psst}'.format(
        psst=read_secret_result['data']['psst'],
    ))

Delete a Secret
-------------------------------

:py:meth:`hvac.api.secrets_engines.KvV1.delete_secret`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v1.delete_secret(
        path='hvac',
    )

    # The following will raise a :py:class:`hvac.exceptions.InvalidPath` exception.
    read_secret_result = client.secrets.kv.v1.read_secret(
        path='hvac',
    )

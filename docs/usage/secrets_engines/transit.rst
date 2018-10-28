Transit Secret Engine
==================

.. note::
    Every method under the :py:attr:`Client class's transit attribute<hvac.v1.Client.transit>` includes a `mount_point` parameter that can be used to address the Transit secret engine under a custom mount path. E.g., If enabling the Transit secret engine using Vault's CLI commands via `vault secret enable -path=my-transit transit`", the `mount_point` parameter in :py:meth:`hvac.api.secrets_engines.Transit` methods would be set to "my-transit".

Enabling the Secret Engine
------------------------

:py:meth:`hvac.v1.Client.enable_secret_backend`

.. code:: python

    import hvac
    client = hvac.Client()

    transit_secret_path = 'company-transit'
    description = 'Secret Engine for use by team members in our company's Transit organization'

    if '%s/' % transit_secret_path not in vault_client.list_secret_backends():
        print('Enabling the transit secret backend at mount_point: {path}'.format(
            path=transit_secret_path,
        ))
        client.enable_secret_backend(
            backend_type='transit',
            description=description,
            mount_point=transit_secret_path,
        )


create-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.create_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.create_key(
    )

read-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.read_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.read_key(
    )

list-keys
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.list_keys`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.list_keys(
    )

delete-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.delete_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.delete_key(
    )

update-key-configuration
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.update_key_configuration`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.update_key_configuration(
    )

rotate-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.rotate_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.rotate_key(
    )

export-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.export_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.export_key(
    )

encrypt-data
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.encrypt_data`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.encrypt_data(
    )

decrypt-data
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.decrypt_data`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.decrypt_data(
    )

rewrap-data
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.rewrap_data`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.rewrap_data(
    )

generate-data-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.generate_data_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.generate_data_key(
    )

generate-random-bytes
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.generate_random_bytes`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.generate_random_bytes(
    )

hash-data
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.hash_data`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.hash_data(
    )

generate-hmac
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.generate_hmac`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.generate_hmac(
    )

sign-data
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.sign_data`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.sign_data(
    )

verify-signed-data
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.verify_signed_data`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.verify_signed_data(
    )

backup-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.backup_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.backup_key(
    )

restore-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.restore_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.restore_key(
    )

trim-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transit.trim_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.transit.trim_key(
    )
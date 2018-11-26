Gcp Auth Method
==================

.. note::
    Every method under the :py:attr:`Client class's gcp attribute<hvac.v1.Client.gcp>` includes a `mount_point` parameter that can be used to address the Gcp secret engine under a custom mount path. E.g., If enabling the Gcp secret engine using Vault's CLI commands via `vault secret enable -path=my-gcp gcp`", the `mount_point` parameter in :py:meth:`hvac.api.secrets_engines.Gcp` methods would be set to "my-gcp".

Enabling the Auth Method
------------------------

:py:meth:`hvac.v1.Client.enable_secret_backend`

.. code:: python

    import hvac
    client = hvac.Client()

    gcp_secret_path = 'company-gcp'
    description = 'Auth method for use by team members in our company's Gcp organization'

    if '%s/' % gcp_secret_path not in vault_client.list_secret_backends():
        print('Enabling the gcp secret backend at mount_point: {path}'.format(
            path=gcp_secret_path,
        ))
        client.enable_secret_backend(
            backend_type='gcp',
            description=description,
            mount_point=gcp_secret_path,
        )


write-config
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.write_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.write_config(
    )

read-config
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.read_config(
    )

create-update-roleset
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.create_or_update_roleset`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.create_or_update_roleset(
    )

rotate-roleset-account
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.rotate_roleset_account`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.rotate_roleset_account(
    )

rotate-roleset-account-key-access_token-roleset-only-
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.rotate_roleset_account_key_access_token_roleset_only`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.rotate_roleset_account_key_access_token_roleset_only(
    )

read-roleset
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.read_roleset`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.read_roleset(
    )

list-rolesets
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.list_rolesets`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.list_rolesets(
    )

generate-secret-iam-service-account-creds-oauth2-access-token
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.generate_secret_iam_service_account_creds_oauth2_access_token`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.generate_secret_iam_service_account_creds_oauth2_access_token(
    )

generate-secret-iam-service-account-creds-service-account-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.generate_secret_iam_service_account_creds_service_account_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.generate_secret_iam_service_account_creds_service_account_key(
    )

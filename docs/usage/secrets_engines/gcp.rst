GCP
===


write-config
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.write_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.gcp.write_config(
    )

read-config
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.gcp.read_config(
    )

create-update-roleset
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.create_or_update_roleset`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.gcp.create_or_update_roleset(
    )

rotate-roleset-account
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.rotate_roleset_account`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.gcp.rotate_roleset_account(
    )

rotate-roleset-account-key-access_token-roleset-only-
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.rotate_roleset_account_key_access_token_roleset_only`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.gcp.rotate_roleset_account_key_access_token_roleset_only(
    )

read-roleset
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.read_roleset`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.gcp.read_roleset(
    )

list-rolesets
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.list_rolesets`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.gcp.list_rolesets(
    )

generate-secret-iam-service-account-creds-oauth2-access-token
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.generate_secret_iam_service_account_creds_oauth2_access_token`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.gcp.generate_secret_iam_service_account_creds_oauth2_access_token(
    )

generate-secret-iam-service-account-creds-service-account-key
-------------------------------

:py:meth:`hvac.api.secrets_engines.Gcp.generate_secret_iam_service_account_creds_service_account_key`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.gcp.generate_secret_iam_service_account_creds_service_account_key(
    )

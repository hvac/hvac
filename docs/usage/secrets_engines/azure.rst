.. _azure-secret-engine:

Azure
=====

.. note::
    Every method under the :py:attr:`Azure class<hvac.api.secrets_engines.Azure>` includes a `mount_point` parameter that can be used to address the Azure secret engine under a custom mount path. E.g., If enabling the Azure secret engine using Vault's CLI commands via `vault secrets enable -path=my-azure azure`", the `mount_point` parameter in :py:meth:`hvac.api.secrets_engines.Azure` methods would need to be set to "my-azure".


Configure
---------

:py:meth:`hvac.api.secrets_engines.Azure.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.azure.configure(
        subscription_id='my-subscription-id',
        tenant_id='my-tenant-id',
    )

Read Config
-----------

:py:meth:`hvac.api.secrets_engines.Azure.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    azure_secret_config = client.secrets.azure.read_config()
    print('The Azure secret engine is configured with a subscription ID of {id}'.format(
        id=azure_secret_config['subscription_id'],
    ))

Delete Config
-------------

:py:meth:`hvac.api.secrets_engines.Azure.delete_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.azure.delete_config()

Create Or Update A Role
-----------------------

:py:meth:`hvac.api.secrets_engines.Azure.create_or_update_role`

.. code:: python

    import hvac
    client = hvac.Client()


    azure_roles = [
        {
            'role_name': "Contributor",
            'scope': "/subscriptions/95e675fa-307a-455e-8cdf-0a66aeaa35ae",
        },
    ]
    client.secrets.azure.create_or_update_role(
        name='my-azure-secret-role',
        azure_roles=azure_roles,
    )

List Roles
----------

:py:meth:`hvac.api.secrets_engines.Azure.list_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    azure_secret_engine_roles = client.secrets.azure.list_roles()
    print('The following Azure secret roles are configured: {roles}'.format(
        roles=','.join(roles['keys']),
    ))


Generate Credentials
--------------------

:py:meth:`hvac.api.secrets_engines.Azure.generate_credentials`

.. code:: python

    import hvac
    from azure.common.credentials import ServicePrincipalCredentials

    client = hvac.Client()
    azure_creds = client.secrets.azure.secret.generate_credentials(
        name='some-azure-role-name',
    )
    azure_spc = ServicePrincipalCredentials(
        client_id=azure_creds['client_id'],
        secret=azure_creds['client_secret'],
        tenant=TENANT_ID,
    )

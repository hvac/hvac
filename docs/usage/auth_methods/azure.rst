.. _azure-auth-method:

Azure Auth Method
==================

.. note::
    Every method under the :py:attr:`Client class's azure attribute<hvac.v1.Client.azure.auth>` includes a `mount_point` parameter that can be used to address the Azure auth method under a custom mount path. E.g., If enabling the Azure auth method using Vault's CLI commands via `vault auth enable -path=my-azure azure`", the `mount_point` parameter in :py:meth:`hvac.api.auth.Azure` methods would be set to "my-azure".

Enabling the Auth Method
------------------------

:py:meth:`hvac.v1.Client.enable_auth_backend`

.. code:: python

    import hvac
    client = hvac.Client()

    azure_auth_path = 'company-azure'
    description = 'Auth method for use by team members in our company's Azure organization'

    if '%s/' % azure_auth_path not in vault_client.list_auth_backends():
        print('Enabling the azure auth backend at mount_point: {path}'.format(
            path=azure_auth_path,
        ))
        client.enable_auth_backend(
            backend_type='azure',
            description=description,
            mount_point=azure_auth_path,
        )


Configure
---------

:py:meth:`hvac.api.auth.Azure.configure`

.. code:: python

    import os
    import hvac
    client = hvac.Client()

    client.azure.configure(
        tenant_id='my-tenant-id'
        resource='my-resource',
        client_id=os.environ.get('AZURE_CLIENT_ID'),
        client_secret=os.environ.get('AZURE_CLIENT_SECRET'),
    )

Read Config
-----------

:py:meth:`hvac.api.auth.Azure.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    read_config = client.azure.read_config()
    print('The configured tenant_id is: {id}'.format(id=read_config['tenant_id'))

Delete Config
-------------

:py:meth:`hvac.api.auth.Azure.delete_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.azure.delete_config()

Create a Role
-------------

:py:meth:`hvac.api.auth.Azure.create_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.azure.create_role(
        name='my-role',
        policies=policies,
        bound_service_principal_ids=bound_service_principal_ids,
    )

Read A Role
-----------

:py:meth:`hvac.api.auth.Azure.read_role`

.. code:: python

    import hvac
    client = hvac.Client()

    role_name = 'my-role'
    read_role_response = client.azure.auth.read_role(
        name=role_name,
        mount_point=self.TEST_MOUNT_POINT,
    )
    print('Policies for role "{name}": {policies}'.format(
        name='my-role',
        policies=','.join(read_role_response['policies']),
    ))

List Roles
----------

:py:meth:`hvac.api.auth.Azure.list_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    roles = client.azure.list_roles()
    print('The following Azure auth roles are configured: {roles}'.format(
        roles=','.join(roles['keys']),
    ))


Delete A Role
-------------

:py:meth:`hvac.api.auth.Azure.delete_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.azure.delete_role(
        name='my-role',
    )

Login
-----

:py:meth:`hvac.api.auth.Azure.login`

.. code:: python

    import hvac
    client = hvac.Client()

    client.azure.login(
        role=role_name,
        jwt='Some MST JWT...',
    )
    client.is_authenticated  # ==> returns True

Active Directory
================

.. contents::

Configure AD Secrets Secrets Engine
-----------------------------------

Configure the AD secrets engine to either manage service accounts or service account libraries.

Source reference: :py:meth:`hvac.api.secrets_engines.activedirectory.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    # Not all these settings may apply to your setup, refer to Vault
    # documentation for context of what to use here

    config_response = client.secrets.activedirectory.configure(
        binddn='username@domain.fqdn', # A upn or DN can be used for this value, Vault resolves the user to a dn silently
        bindpass='***********',
        url='ldaps://domain.fqdn',
        userdn='CN=Users,DN=domain,DN=fqdn',
        upndomain='domain.fqdn',
        ttl=60,
        max_ttl=120
    )
    print(config_response)


Read Config
-----------

Return the AD Secret Engine configuration.

Source reference: :py:meth:`hvac.api.secrets_engines.activedirectory.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    config_response = client.secrets.activedirectory.read_config()


Create or Update Role
---------------------

Create or Update a role which allows the retrieval and rotation of an AD account. Retrieve and rotate the actual credential via generate_credentials().

Source reference: :py:meth:`hvac.api.secrets_engines.activedirectory.create_or_update_role`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    role_response = client.secrets.activedirectory.create_or_update_role(
        name='sql-service-account',
        service_account_name='svc-sqldb-petshop@domain.fqdn',
        ttl=60)


Read Role
---------

Retrieve the role configuration which allows the retrieval and rotation of an AD account. Retrieve and rotate the actual credential via generate_credentials().

Source reference: :py:meth:`hvac.api.secrets_engines.activedirectory.read_role`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    role_response = client.secrets.activedirectory.read_role(name='sql-service-account')


List Roles
----------

List all configured roles which allows the retrieval and rotation of an AD account. Retrieve and rotate the actual credential via generate_credentials().

Source reference: :py:meth:`hvac.api.secrets_engines.activedirectory.list_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    all_roles = client.secrets.activedirectory.list_roles()


Delete Role
-----------

Remove the role configuration which allows the retrieval and rotation of an AD account. 

The account is retained in Active Directory, but the password will be whatever Vault had rotated it to last. 
To regain control, the password will need to be reset via Active Directory.

Source reference: :py:meth:`hvac.api.secrets_engines.activedirectory.delete_role`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    deletion_response = client.secrets.activedirectory.delete_role(name='sql-service-account')

Generate Credentials
--------------------

Retrieve a service account password from AD. Return the previous password (if known). Vault shall rotate
the password before returning it, if it has breached its configured ttl.

Source reference: :py:meth:`hvac.api.secrets_engines.activedirectory.generate_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    gen_creds_response = client.secrets.activedirectory.generate_credentials(
        name='hvac-role',
    )
    print('Retrieved Service Account Password: {access} (Current) / {secret} (Old)'.format(
        access=gen_creds_response['data']['current_password'],
        secret=gen_creds_response['data']['old_password'],
    ))

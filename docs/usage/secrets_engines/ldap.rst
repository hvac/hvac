LDAP
================

.. contents::

Configure LDAP Secrets Secrets Engine
-------------------------------------

Configure the LDAP secrets engine to either manage service accounts or service account libraries.

Source reference: :py:meth:`hvac.api.secrets_engines.ldap.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    # Not all these settings may apply to your setup, refer to Vault
    # documentation for context of what to use here

    config_response = client.secrets.ldap.configure(
        binddn='username@domain.fqdn', # A upn or DN can be used for this value, Vault resolves the user to a dn silently
        bindpass='***********',
        url='ldaps://domain.fqdn',
        userdn='cn=Users,dn=domain,dn=fqdn',
        upndomain='domain.fqdn',
        userattr="cn",
        schema="openldap",
        skip_import_rotation=False
    )
    print(config_response)


Read Config
-----------

Return the LDAP Secret Engine configuration.

Source reference: :py:meth:`hvac.api.secrets_engines.ldap.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    config_response = client.secrets.ldap.read_config()


Rotate Root
---------------------------

Rotate the password for the binddn entry used to manage LDAP. This generated password will only be known to Vault and will not be retrievable once rotated.

Source reference: :py:meth:`hvac.api.secrets_engines.ldap.rotate_root`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    rotate_response = client.secrets.ldap.rotate_root()


Create or Update Static Role
----------------------------

Create or Update a role which allows the retrieval and rotation of an LDAP account. Retrieve and rotate the actual credential via generate_static_credentials().

Source reference: :py:meth:`hvac.api.secrets_engines.ldap.create_or_update_static_role`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    role_response = client.secrets.ldap.create_or_update_static_role(
        name='hvac-role',
        username='sql-service-account',
        dn='cn=sql-service-account,dc=petshop,dc=com',
        rotation_period="60s"
        skip_import_rotation=False)


Read Static Role
----------------

Retrieve the role configuration which allows the retrieval and rotation of an LDAP account. Retrieve and rotate the actual credential via generate_static_credentials().

Source reference: :py:meth:`hvac.api.secrets_engines.ldap.read_static_role`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    role_response = client.secrets.ldap.read_static_role(name='sql-service-account')


List Static Roles
-----------------

List all configured roles which allows the retrieval and rotation of an LDAP account. Retrieve and rotate the actual credential via generate_static_credentials().

Source reference: :py:meth:`hvac.api.secrets_engines.ldap.list_static_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    all_static_roles = client.secrets.ldap.list_static_roles()


Delete Static Role
------------------

Remove the role configuration which allows the retrieval and rotation of an LDAP account. 

Passwords are not rotated upon deletion of a static role. The password should be manually rotated prior to deleting the role or revoking access to the static role.

Source reference: :py:meth:`hvac.api.secrets_engines.ldap.delete_static_role`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    deletion_response = client.secrets.ldap.delete_static_role(name='sql-service-account')


Generate Static Credentials
---------------------------

Retrieve a service account password from LDAP. Return the previous password (if known). Vault shall rotate
the password before returning it, if it has breached its configured ttl.

Source reference: :py:meth:`hvac.api.secrets_engines.ldap.generate_static_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    gen_creds_response = client.secrets.ldap.generate_static_credentials(
        name='hvac-role',
    )
    print('Retrieved Service Account Password: {access} (Current) / {secret} (Old)'.format(
        access=gen_creds_response['data']['current_password'],
        secret=gen_creds_response['data']['old_password'],
    ))


Rotate Static Credentials
---------------------------

Manually rotate the password of an existing role.

Source reference: :py:meth:`hvac.api.secrets_engines.ldap.rotate_static_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    # Authenticate to Vault using client.auth.x

    rotate_response = client.secrets.ldap.rotate_static_credentials(name='hvac-role')
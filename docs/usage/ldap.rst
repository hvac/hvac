LDAP Auth Method
================

.. note::
    Every method under the :py:attr:`Client class's ldap attribute<hvac.v1.Client.ldap>` includes a `mount_point` parameter that can be used to address the LDAP auth method under a custom mount path. E.g., If enabling the LDAP auth method using Vault's CLI commands via `vault auth enable -path=my-ldap ldap`", the `mount_point` parameter in :py:meth:`hvac.api.auth.Ldap` methods would be set to "my-ldap".

Enabling the LDAP Auth Method
-----------------------------

:py:meth:`hvac.v1.Client.enable_auth_backend`

.. code:: python

    import hvac
    client = hvac.Client()

    ldap_auth_path = 'company-ldap'
    description = "Auth method for use by team members in our company's LDAP organization"

    if '%s/' % ldap_auth_path not in vault_client.list_auth_backends():
        print('Enabling the ldap auth backend at mount_point: {path}'.format(
            path=ldap_auth_path,
        ))
        client.enable_auth_backend(
            backend_type='ldap',
            description=description,
            mount_point=ldap_auth_path,
        )


Configure LDAP Auth Method Settings
-----------------------------------

:py:meth:`hvac.api.auth.Ldap.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    client.ldap.configure(
        user_dn='dc=users,dc=hvac,dc=network',
        group_dn='ou=groups,dc=hvac,dc=network',
        url='ldaps://ldap.hvac.network:12345',
        bind_dn='cn=admin,dc=hvac,dc=network',
        bind_pass='ourverygoodadminpassword'
        user_attr='uid',
        group_attr='cn',
    )

Reading the LDAP Auth Method Configuration
------------------------------------------

:py:meth:`hvac.api.auth.Ldap.read_configuration`

.. code:: python

    import hvac
    client = hvac.Client()

    ldap_configuration = client.ldap.read_configuration()
    print('The LDAP auth method is configured with a LDAP server URL of: {url}'.format(
        url=ldap_configuration['data']['url']
    )

Create or Update a LDAP Group Mapping
-------------------------------------

:py:meth:`hvac.api.auth.Ldap.create_or_update_group`

.. code:: python

    import hvac
    client = hvac.Client()

    client.ldap.create_or_update_group(
        name='some-dudes',
        policies=['policy-for-some-dudes'],
    )

List LDAP Group Mappings
------------------------

:py:meth:`hvac.api.auth.Ldap.list_groups`

.. code:: python

    import hvac
    client = hvac.Client()

    ldap_groups = client.ldap.list_groups()
    print('The following groups are configured in the LDAP auth method: {groups}'.format(
        groups=','.join(ldap_groups['data']['keys'])
    )


Read LDAP Group Mapping
-----------------------

:py:meth:`hvac.api.auth.Ldap.read_group`

.. code:: python

    import hvac
    client = hvac.Client()

    some_dudes_ldap_group = client.ldap.read_group(
        name='somedudes',
    )
    print('The "somedudes" group in the LDAP auth method are mapped to the following policies: {policies}'.format(
        policies=','.join(some_dudes_ldap_group['data']['policies'])
    )

Deleting a LDAP Group Mapping
-----------------------------

:py:meth:`hvac.api.auth.Ldap.delete_group`

.. code:: python

    import hvac
    client = hvac.Client()

    client.ldap.delete_group(
        name='some-group',
    )

Creating or Updating a LDAP User Mapping
----------------------------------------

:py:meth:`hvac.api.auth.Ldap.create_or_update_user`

.. code:: python

    import hvac
    client = hvac.Client()

    client.ldap.create_or_update_user(
        username='somedude',
        policies=['policy-for-some-dudes'],
    )

Listing LDAP User Mappings
--------------------------

:py:meth:`hvac.api.auth.Ldap.list_users`

.. code:: python

    import hvac
    client = hvac.Client()

    ldap_users = client.ldap.list_users()
    print('The following users are configured in the LDAP auth method: {users}'.format(
        users=','.join(ldap_users['data']['keys'])
    )

Reading a LDAP User Mapping
---------------------------

:py:meth:`hvac.api.auth.Ldap.read_user`

.. code:: python

    import hvac
    client = hvac.Client()

    some_dude_ldap_user = client.ldap.read_user(
        username='somedude'
    )
    print('The "somedude" user in the LDAP auth method is mapped to the following policies: {policies}'.format(
        policies=','.join(some_dude_ldap_user['data']['policies'])
    )

Deleting a Configured User Mapping
----------------------------------

:py:meth:`hvac.api.auth.Ldap.delete_user`

.. code:: python

    import hvac
    client = hvac.Client()

    client.ldap.delete_user(
        username='somedude',
    )

Authentication / Login
----------------------

:py:meth:`hvac.api.auth.Ldap.login_with_user`

For a LDAP backend mounted under a non-default (ldap) path.
E.g., via Vault CLI with `vault auth enable -path=prod-ldap ldap`

.. code:: python

    from getpass import getpass

    import hvac

    service_account_username = 'someuser'
    password_prompt = 'Please enter your password for the LDAP authentication backend: '
    service_account_password = getpass(prompt=password_prompt)

    client = hvac.Client()

    # Here the mount_point parameter corresponds to the path provided when enabling the backend
    client.ldap.login(
        username=service_account_username,
        password=service_account_password,
        mount_point='prod-ldap'
    )
    print(client.is_authenticated)  # => True

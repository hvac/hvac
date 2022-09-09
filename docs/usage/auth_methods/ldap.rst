LDAP
====

.. note::
    Every method under the :py:attr:`Client class's ldap attribute<hvac.v1.Client.ldap>` includes a `mount_point` parameter that can be used to address the LDAP auth method under a custom mount path. E.g., If enabling the LDAP auth method using Vault's CLI commands via `vault auth enable -path=my-ldap ldap`", the `mount_point` parameter in :py:meth:`hvac.api.auth_methods.Ldap` methods would be set to "my-ldap".

Enabling the LDAP Auth Method
-----------------------------

:py:meth:`hvac.api.SystemBackend.enable_auth_method`

.. code:: python

    import hvac
    client = hvac.Client()

    ldap_auth_path = 'company-ldap'
    description = "Auth method for use by team members in our company's LDAP organization"

    if '%s/' % ldap_auth_path not in vault_client.sys.list_auth_methods()['data']:
        print('Enabling the ldap auth backend at mount_point: {path}'.format(
            path=ldap_auth_path,
        ))
        client.sys.enable_auth_method(
            method_type='ldap',
            description=description,
            path=ldap_auth_path,
        )


Configure LDAP Auth Method Settings
-----------------------------------

:py:meth:`hvac.api.auth_methods.Ldap.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.ldap.configure(
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

:py:meth:`hvac.api.auth_methods.Ldap.read_configuration`

.. code:: python

    import hvac
    client = hvac.Client()

    ldap_configuration = client.auth.ldap.read_configuration()
    print('The LDAP auth method is configured with a LDAP server URL of: {url}'.format(
        url=ldap_configuration['data']['url']
    )

Create or Update a LDAP Group Mapping
-------------------------------------

:py:meth:`hvac.api.auth_methods.Ldap.create_or_update_group`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.ldap.create_or_update_group(
        name='some-dudes',
        policies=['policy-for-some-dudes'],
    )

List LDAP Group Mappings
------------------------

:py:meth:`hvac.api.auth_methods.Ldap.list_groups`

.. code:: python

    import hvac
    client = hvac.Client()

    ldap_groups = client.auth.ldap.list_groups()
    print('The following groups are configured in the LDAP auth method: {groups}'.format(
        groups=','.join(ldap_groups['data']['keys'])
    )


Read LDAP Group Mapping
-----------------------

:py:meth:`hvac.api.auth_methods.Ldap.read_group`

.. code:: python

    import hvac
    client = hvac.Client()

    some_dudes_ldap_group = client.auth.ldap.read_group(
        name='somedudes',
    )
    print('The "somedudes" group in the LDAP auth method are mapped to the following policies: {policies}'.format(
        policies=','.join(some_dudes_ldap_group['data']['policies'])
    )

Deleting a LDAP Group Mapping
-----------------------------

:py:meth:`hvac.api.auth_methods.Ldap.delete_group`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.ldap.delete_group(
        name='some-group',
    )

Creating or Updating a LDAP User Mapping
----------------------------------------

:py:meth:`hvac.api.auth_methods.Ldap.create_or_update_user`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.ldap.create_or_update_user(
        username='somedude',
        policies=['policy-for-some-dudes'],
    )

Listing LDAP User Mappings
--------------------------

:py:meth:`hvac.api.auth_methods.Ldap.list_users`

.. code:: python

    import hvac
    client = hvac.Client()

    ldap_users = client.auth.ldap.list_users()
    print('The following users are configured in the LDAP auth method: {users}'.format(
        users=','.join(ldap_users['data']['keys'])
    )

Reading a LDAP User Mapping
---------------------------

:py:meth:`hvac.api.auth_methods.Ldap.read_user`

.. code:: python

    import hvac
    client = hvac.Client()

    some_dude_ldap_user = client.auth.ldap.read_user(
        username='somedude'
    )
    print('The "somedude" user in the LDAP auth method is mapped to the following policies: {policies}'.format(
        policies=','.join(some_dude_ldap_user['data']['policies'])
    )

Deleting a Configured User Mapping
----------------------------------

:py:meth:`hvac.api.auth_methods.Ldap.delete_user`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.ldap.delete_user(
        username='somedude',
    )

Authentication / Login
----------------------

:py:meth:`hvac.api.auth_methods.Ldap.login_with_user`

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
    client.auth.ldap.login(
        username=service_account_username,
        password=service_account_password,
        mount_point='prod-ldap'
    )
    print(client.is_authenticated())  # => True

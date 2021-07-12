Okta
====

.. note::
    Every method under the :py:attr:`Client class's okta attribute<hvac.v1.Client.okta>` includes a `mount_point` parameter that can be used to address the Okta auth method under a custom mount path. E.g., If enabling the Okta auth method using Vault's CLI commands via `vault secret enable -path=my-okta okta`", the `mount_point` parameter in Source reference: :py:meth:`hvac.api.auth_methods.Okta` methods would be set to "my-okta".

Enabling the Auth Method
------------------------

Source reference: :py:meth:`hvac.v1.client.sys.enable_secrets_engine`

.. code:: python

    import hvac
    client = hvac.Client()

    okta_path = 'company-okta'
    description = 'Auth method for use by team members in our company's Okta organization'

    if '%s/' % okta_path not in vault_client.sys.list_auth_methods()['data']:
        print('Enabling the okta secret backend at mount_point: {path}'.format(
            path=okta_secret_path,
        ))
        client.sys.enable_auth_method(
            method_type='okta',
            description=description,
            path=okta_secret_path,
        )


Configure
---------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.okta.configure(
        org_name='hvac-project'
    )

Read Config
-------------------------------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    okta_config = client.auth.okta.read_config()
    print('The Okta auth method at path /okta has a configured organization name of: {name}'.format(
        name=okta_config['data']['org_name'],
    ))

List Users
----------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.list_users`

.. code:: python

    import hvac
    client = hvac.Client()

    users = client.auth.okta.list_users()
    print('The following Okta users are registered: {users}'.format(
        users=','.join(users['data']['keys']),
    ))

Register User
-------------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.register_user`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.okta.register_user(
        username='hvac-person',
        policies=['hvac-admin'],
    )

Read User
---------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.read_user`

.. code:: python

    import hvac
    client = hvac.Client()

    read_user = client.auth.okta.read_user(
        username='hvac-person',
    )
    print('Okta user "{name}" has the following attached policies: {policies}'.format(
        name='hvac-person',
        policies=', '.join(read_user['data']['policies'],
    ))

Delete User
-----------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.delete_user`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.okta.delete_user(
        username='hvac-person'
    )

List Groups
-----------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.list_groups`

.. code:: python

    import hvac
    client = hvac.Client()

    groups = client.auth.okta.list_groups()
    print('The following Okta groups are registered: {groups}'.format(
        groups=','.join(groups['data']['keys']),
    ))

Register Group
--------------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.register_group`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.okta.register_group(
        name='hvac-group',
        policies=['hvac-group-members'],
    )

Read Group
----------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.read_group`

.. code:: python

    import hvac
    client = hvac.Client()

    read_group = client.auth.okta.read_group(
        name='hvac-group',
    )
    print('Okta group "{name}" has the following attached policies: {policies}'.format(
        name='hvac-group',
        policies=', '.join(read_group['data']['policies'],
    ))

Delete Group
------------

Source reference: :py:meth:`hvac.api.auth_methods.Okta.delete_group`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.okta.delete_group(
        name='hvac-group',
    )

Login
-----

Source reference: :py:meth:`hvac.api.auth_methods.Okta.login`

.. code:: python

    from getpass import getpass

    import hvac
    client = hvac.Client()


    password_prompt = 'Please enter your password for the Okta authentication backend: '
    okta_password = getpass(prompt=password_prompt)

    client.auth.okta.login(
        username='hvac-person',
        password=okta_password,
    )

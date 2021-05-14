Approle
=======

.. contents::

Enabling
--------

:py:meth:`hvac.api.system_backend.Auth.enable_auth_method`

.. code:: python

    import hvac
    client = hvac.Client()

    client.sys.enable_auth_method(
        method_type='approle',
    )

    # Mount approle auth method under a different path:
    client.sys.enable_auth_method(
        method_type='approle',
        path='my-approle',
    )

Authentication
--------------

:py:meth:`hvac.api.auth_methods.AppRole.login`

.. code:: python

    import hvac
    client = hvac.Client()


    client.auth.approle.login(
        role_id='<some_role_id>',
        secret_id='<some_secret_id>',
    )

Create or Update AppRole
------------------------

:py:meth:`hvac.api.auth_methods.AppRole.create_or_update_approle`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.approle.create_or_update_approle(
        role_name='some-role',
        token_policies=['some-policy'],
        token_type='service,
    )

Read Role ID
------------

:py:meth:`hvac.api.auth_methods.AppRole.read_role_id`

.. code:: python

    import hvac
    client = hvac.Client()

    resp = client.auth.approle.read_role_id(
        role_name='some-role',
    )
    print(f'AppRole role ID for some-role: {resp["data"]["role_id"]}')


Generate Secret ID
------------------

:py:meth:`hvac.api.auth_methods.AppRole.generate_secret_id`

.. code:: python

    import hvac
    client = hvac.Client()

    resp = client.auth.approle.generate_secret_id(
        role_name='some-role',
        cidr_list=['127.0.0.1/32'],
    )
    print(f'AppRole secret ID for some-role: {resp["data"]["secret_id"]}')

JWT/OIDC
========

.. contents::

.. note::
    The :py:class:`hvac.api.auth_methods.JWT` and :py:class:`hvac.api.auth_methods.OIDC` share all the same methods.
    They only differ in the default path their methods will use. I.e., `v1/auth/jwt` versus `v1/auth/oidc`.

Enabling
--------

.. code:: python

    import hvac
    client = hvac.Client()

    # For JWT
    client.sys.enable_auth_method(
        method_type='jwt',
    )

    # For OIDC
    client.sys.enable_auth_method(
        method_type='oidc',
    )


Configure
---------

:py:meth:`hvac.api.auth_methods.JWT.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.jwt.configure(
        oidc_discovery_url=oidc_discovery_url,
        oidc_discovery_ca_pem=some_ca_file_contents,
    )

    # or

    client.auth.oidc.configure(
        oidc_discovery_url=oidc_discovery_url,
        oidc_discovery_ca_pem=some_ca_file_contents,
    )

Read Config
-----------

:py:meth:`hvac.api.auth_methods.JWT.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    read_response = client.auth.jwt.read_config()
    # or
    read_response = client.auth.oidc.read_config()

    discovery_url = read_response['data']['oidc_discovery_url']
    print('Current OIDC discovery URL is set to: %s' % discovery_url)

Create Role
-----------

:py:meth:`hvac.api.auth_methods.JWT.create_role`

.. code:: python

    import hvac
    client = hvac.Client()

    role_name = 'hvac'
    allowed_redirect_uris = ['https://localhost:8200/jwt-test/callback']
    user_claim = 'https://vault/user'

    # JWT
    client.auth.jwt.create_role(
        name=role_name,
        role_type='jwt',
        allowed_redirect_uris=allowed_redirect_uris,
        user_claim='sub',
        bound_audiences=['12345'],
    )

    # OIDC
    client.auth.oidc.create_role(
        name=role_name,
        allowed_redirect_uris=allowed_redirect_uris,
        user_claim=user_claim,
    )

Read Role
---------

:py:meth:`hvac.api.auth_methods.JWT.read_role`

.. code:: python

    import hvac
    client = hvac.Client()

    response = client.auth.jwt.read_role(
        name='hvac',
    )
    print('hvac role has a user_claim setting of: %s' % response['data']['user_claim'])

List Roles
----------

:py:meth:`hvac.api.auth_methods.JWT.list_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    list_resp = client.auth.jwt.list_roles()
    print('Configured roles: %s' % ', '.join(list_resp['data']['keys']))

Delete Role
-----------

:py:meth:`hvac.api.auth_methods.JWT.delete_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.jwt.delete_role(
        name='hvac',
    )

OIDC Authorization URL Request
-------------------------------

:py:meth:`hvac.api.auth_methods.JWT.oidc_authorization_url_request`

.. code:: python

    import requests
    import hvac
    client = hvac.Client()

    auth_url_response = client.auth.oidc.oidc_authorization_url_request(
        role='hvac',
        redirect_uri='https://localhost:8200/v1/auth/oidc/oidc/callback',
    )
    auth_url = auth_url_response['data']['auth_url']
    print('Requested auth URL is: %s' % auth_url)

    response = requests.post(
        url=auth_url,
        # ...,
    )
    print('Client token returned: %s' % response['auth']['client_token'])


JWT Login
---------

:py:meth:`hvac.api.auth_methods.JWT.jwt_login`

.. code:: python

    import hvac
    client = hvac.Client()

    response = client.auth.jwt.jwt_login(
        role=role_name,
        jwt=generate_token_response['data']['token'],
    )
    print('Client token returned: %s' % response['auth']['client_token'])

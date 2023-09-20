Auth Methods
============

.. toctree::
   :maxdepth: 2

   approle
   aws
   azure
   gcp
   github
   jwt-oidc
   kubernetes
   ldap
   legacymfa
   okta
   token
   userpass

Authenticate to different auth backends
---------------------------------------

.. code:: python


    # App ID
    client.auth_app_id('MY_APP_ID', 'MY_USER_ID')

    # GitHub
    client.auth.github.login('MY_GITHUB_TOKEN')

    # TLS
    client = Client(cert=('path/to/cert.pem', 'path/to/key.pem'))
    client.auth.cert.login()

    # Non-default mount point (available on all auth types)
    client.auth.userpass.login('MY_USERNAME', 'MY_PASSWORD', mount_point='CUSTOM_MOUNT_POINT')

    # Authenticating without changing to new token (available on all auth types)
    result = client.auth.github.login('MY_GITHUB_TOKEN', use_token=False)
    print(result['auth']['client_token']) # => u'NEW_TOKEN'

    # Custom or unsupported auth type
    params = {
        'username': 'MY_USERNAME',
        'password': 'MY_PASSWORD',
        'custom_param': 'MY_CUSTOM_PARAM',
    }

    result = client.login('/v1/auth/CUSTOM_AUTH/login', json=params)

    # Logout
    client.logout()

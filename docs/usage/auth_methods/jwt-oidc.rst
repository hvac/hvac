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

This is equivalent to `vault login -method=oidc`

.. code:: python

    import webbrowser
    import http.server
    import hvac
    import urllib.parse

    # CHANGEME: these params might have to be changed to match your Vault configuration.
    # Specifically
    # 1. auth/oidc/role/XXX allowed_redirect_uris must contain the
    #    OIDC_REDIRECT_URI string used below.
    # 2. Role must match your environment's role for this client.
    OIDC_CALLBACK_PORT = 8250
    OIDC_REDIRECT_URI = f'http://localhost:{OIDC_CALLBACK_PORT}/oidc/callback'
    ROLE = 'hvac' # Use None (not empty string) for the default Role
    SELF_CLOSING_PAGE = '''
    <!doctype html>
    <html>
    <head>
    <script>
    // Closes IE, Edge, Chrome, Brave
    window.onload = function load() {
      window.open('', '_self', '');
      window.close();
    };
    </script>
    </head>
    <body>
      <p>Authentication successful, you can close the browser now.</p>
      <script>
        // Needed for Firefox security
        setTimeout(function() {
              window.close()
        }, 5000);
      </script>
    </body>
    </html>
    '''

    def main():
        client = hvac.Client()

        auth_url_response = client.auth.oidc.oidc_authorization_url_request(
            role=ROLE,
            redirect_uri=OIDC_REDIRECT_URI,
        )
        auth_url = auth_url_response['data']['auth_url']
        if auth_url == '':
            return None # TODO: throw a nicer error

        params = urllib.parse.parse_qs(auth_url.split('?')[1])
        auth_url_nonce = params['nonce'][0]
        auth_url_state = params['state'][0]

        webbrowser.open(auth_url)
        token = login_oidc_get_token()

        auth_result = client.auth.oidc.oidc_callback(
            code=token,
            path='oidc',
            nonce=auth_url_nonce,
            state=auth_url_state,
        )
        new_token = auth_result['auth']['client_token']
        print(f'Client token returned: {new_token}')

        # If you want to continue using the client here
        # update the client to use the new token
        client.token = new_token
        return client

    # handles the callback
    def login_oidc_get_token():
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class HttpServ(HTTPServer):
            def __init__(self, *args, **kwargs):
                HTTPServer.__init__(self, *args, **kwargs)
                self.token = None

        class AuthHandler(BaseHTTPRequestHandler):
            token = ''

            def do_GET(self):
                params = urllib.parse.parse_qs(self.path.split('?')[1])
                self.server.token = params['code'][0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(str.encode(SELF_CLOSING_PAGE))

        server_address = ('', OIDC_CALLBACK_PORT)
        httpd = HttpServ(server_address, AuthHandler)
        httpd.handle_request()
        return httpd.token

    if __name__ == '__main__':
        client = main()
        if client and client.is_authenticated():
            # Do something
            pass


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

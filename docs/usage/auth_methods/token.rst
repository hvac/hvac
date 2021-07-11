Token
=====

Authentication
--------------

.. code:: python

    # Token
    client.token = 'MY_TOKEN'
    assert client.is_authenticated() # => True

Token Management
----------------

Token creation and revocation:

.. code:: python

    token = client.auth.token.create(policies=['root'], lease='1h')

    current_token = client.auth.token.lookup()
    some_other_token = client.auth.token.lookup('xxx')

    client.auth.token.revoke('xxx')
    client.auth.token.revoke('yyy', orphan=True)

    client.auth.token.renew('aaa')


Lookup and revoke tokens via a token accessor:

.. code:: python

    token = client.auth.token.create(policies=['root'], lease='1h')
    token_accessor = token['auth']['accessor']

    same_token = client.auth.token.lookup(token_accessor, accessor=True)
    client.auth.token.revoke(token_accessor, accessor=True)


Wrapping/unwrapping a token:

.. code:: python

    wrap = client.auth.token.create(policies=['root'], lease='1h', wrap_ttl='1m')
    result = self.client.unwrap(wrap['wrap_info']['token'])


Login with a wrapped token:

.. code:: python

    wrap = client.auth.token.create(policies=['root'], lease='1h', wrap_ttl='1m')
    new_client = hvac.Client()
    new_client.auth_cubbyhole(wrap['wrap_info']['token'])
    assert new_client.token != wrapped_token['wrap_info']['token']

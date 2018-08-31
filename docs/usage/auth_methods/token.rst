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

    token = client.create_token(policies=['root'], lease='1h')

    current_token = client.lookup_token()
    some_other_token = client.lookup_token('xxx')

    client.revoke_token('xxx')
    client.revoke_token('yyy', orphan=True)

    client.revoke_token_prefix('zzz')

    client.renew_token('aaa')


Lookup and revoke tokens via a token accessor:

.. code:: python

    token = client.create_token(policies=['root'], lease='1h')
    token_accessor = token['auth']['accessor']

    same_token = client.lookup_token(token_accessor, accessor=True)
    client.revoke_token(token_accessor, accessor=True)

Wrapping/unwrapping a token:


.. code:: python

    wrap = client.create_token(policies=['root'], lease='1h', wrap_ttl='1m')
    result = self.client.unwrap(wrap['wrap_info']['token'])

Usage
=====

.. toctree::
   :maxdepth: 2

   secrets_engines/index
   auth_methods/index
   system_backend/index

Initialize and seal/unseal
--------------------------

.. code:: python

    print(client.sys.is_initialized()) # => False

    shares = 5
    threshold = 3

    result = client.sys.initialize(shares, threshold)

    root_token = result['root_token']
    keys = result['keys']

    print(client.sys.is_initialized()) # => True

    print(client.sys.is_sealed()) # => True

    # unseal with individual keys
    client.sys.unseal(keys[0])
    client.sys.unseal(keys[1])
    client.sys.unseal(keys[2])

    # unseal with multiple keys until threshold met
    client.sys.unseal_multi(keys)

    print(client.sys.is_sealed()) # => False

    client.sys.seal()

    print(client.sys.is_sealed()) # => True

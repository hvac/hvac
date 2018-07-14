Initialize and seal/unseal
--------------------------

.. code:: python

    print(client.is_initialized()) # => False

    shares = 5
    threshold = 3

    result = client.initialize(shares, threshold)

    root_token = result['root_token']
    keys = result['keys']

    print(client.is_initialized()) # => True

    print(client.is_sealed()) # => True

    # unseal with individual keys
    client.unseal(keys[0])
    client.unseal(keys[1])
    client.unseal(keys[2])

    # unseal with multiple keys until threshold met
    client.unseal_multi(keys)

    print(client.is_sealed()) # => False

    client.seal()

    print(client.is_sealed()) # => True

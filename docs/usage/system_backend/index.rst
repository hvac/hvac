System Backend
==============

.. toctree::
   :maxdepth: 2

   audit
   auth
   health
   init
   key
   leader
   lease
   mount
   policy
   seal

.. contents::

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

View and Manage Leases
----------------------

Read a lease:

.. versionadded:: 0.6.2

.. code-block:: python

    >>> client.read_lease(lease_id='pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f')
    {'lease_id': '', 'warnings': None, 'wrap_info': None, 'auth': None, 'lease_duration': 0, 'request_id': 'a08768dc-b14e-5e2d-f291-4702056f8d4e', 'data': {'last_renewal': None, 'ttl': 259145, 'expire_time': '2018-07-19T06:20:02.000046424-05:00', 'id': 'pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f', 'renewable': False, 'issue_time': '2018-07-16T06:20:02.918474523-05:00'}, 'renewable': False}

Renewing a lease:

.. code-block:: python

    >>> client.renew_secret(lease_id='pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f')
    {'lease_id': 'pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f', 'lease_duration': 2764790, 'renewable': True}

Revoking a lease:

.. code-block:: python

    >>> client.revoke_secret(lease_id='pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f')

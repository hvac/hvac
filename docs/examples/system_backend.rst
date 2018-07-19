System Backend
==============

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

Manipulate auth backends
------------------------

.. code:: python

    backends = client.list_auth_backends()

    client.enable_auth_backend('userpass', mount_point='customuserpass')
    client.disable_auth_backend('github')

Manipulate secret backends
--------------------------

.. code:: python

    backends = client.list_secret_backends()

    client.enable_secret_backend('aws', mount_point='aws-us-east-1')
    client.disable_secret_backend('mysql')

    client.tune_secret_backend('generic', mount_point='test', default_lease_ttl='3600s', max_lease_ttl='8600s')
    client.get_secret_backend_tuning('generic', mount_point='test')

    client.remount_secret_backend('aws-us-east-1', 'aws-east')

Manipulate policies
-------------------

.. code:: python

    policies = client.list_policies() # => ['root']

    policy = """
    path "sys" {
      policy = "deny"
    }

    path "secret" {
      policy = "write"
    }

    path "secret/foo" {
      policy = "read"
    }
    """

    client.set_policy('myapp', policy)

    client.delete_policy('oldthing')

    policy = client.get_policy('mypolicy')

    # Requires pyhcl to automatically parse HCL into a Python dictionary
    policy = client.get_policy('mypolicy', parse=True)

Manipulate audit backends
-------------------------

.. code:: python

    backends = client.list_audit_backends()

    options = {
        'path': '/tmp/vault.log',
        'log_raw': True,
    }

    client.enable_audit_backend('file', options=options, name='somefile')
    client.disable_audit_backend('oldfile')

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

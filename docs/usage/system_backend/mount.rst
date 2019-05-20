Mount
=====

.. contents::
   :local:
   :depth: 1


Manipulate secret backends
--------------------------

.. doctest:: sys_mount

    backends = client.sys.list_mounted_secrets_engines()['data']

    client.sys.enable_secrets_engine('aws', path='aws-us-east-1')
    client.sys.disable_secrets_engine('mysql')

    client.sys.tune_mount_configuration(path='test', default_lease_ttl='3600s', max_lease_ttl='8600s')
    client.sys.read_mount_configuration(path='test')

    client.sys.move_backend('aws-us-east-1', 'aws-east')


List Mounted Secrets Engines
----------------------------

.. automethod:: hvac.api.system_backend.Mount.list_mounted_secrets_engines
   :noindex:

Examples
````````

.. testcode:: sys_mount

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    secrets_engines_list = client.sys.list_mounted_secrets_engines()['data']
    print('The following secrets engines are mounted: %s' % ', '.join(sorted(secrets_engines_list.keys())))

Example output:

.. testoutput:: sys_mount

    The following secrets engines are mounted: cubbyhole/, identity/, secret/, sys/


Enable Secrets Engine
---------------------

.. automethod:: hvac.api.system_backend.Mount.enable_secrets_engine
   :noindex:

Examples
````````

.. testcode:: sys_mount

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.enable_secrets_engine(
        backend_type='kv',
        path='hvac-kv',
    )


Disable Secrets Engine
----------------------

.. automethod:: hvac.api.system_backend.Mount.disable_secrets_engine
   :noindex:

Examples
````````

.. testsetup:: sys_mount_disable

    client.sys.enable_secrets_engine(
        backend_type='kv',
        path='hvac-kv',
    )

.. testcode:: sys_mount_disable

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.disable_secrets_engine(
        path='hvac-kv',
    )


Read Mount Configuration
------------------------

.. automethod:: hvac.api.system_backend.Mount.read_mount_configuration
   :noindex:

Examples
````````

.. testcode:: sys_mount

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    secret_backend_tuning = client.sys.read_mount_configuration(path='hvac-kv')
    print('The max lease TTL for the "hvac-kv" backend is: {max_lease_ttl}'.format(
        max_lease_ttl=secret_backend_tuning['data']['max_lease_ttl'],
     ))

Example output:

.. testoutput:: sys_mount

    The max lease TTL for the "hvac-kv" backend is: 2764800


Tune Mount Configuration
------------------------

.. automethod:: hvac.api.system_backend.Mount.tune_mount_configuration
   :noindex:

Examples
````````

.. testcode:: sys_mount

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.tune_mount_configuration(
        path='hvac-kv',
        default_lease_ttl='3600s',
        max_lease_ttl='8600s',
    )


Move Backend
------------

.. automethod:: hvac.api.system_backend.Mount.move_backend
   :noindex:

Examples
````````

.. testsetup:: sys_mount_move

    client.sys.enable_secrets_engine(
        backend_type='kv',
        path='hvac-kv',
    )

.. testcode:: sys_mount_move

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.move_backend(
        from_path='hvac-kv',
        to_path='kv-hvac',
    )

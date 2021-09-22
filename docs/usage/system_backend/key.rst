Key
===

.. contents::
   :local:
   :depth: 1

Read Root Generation Progress
-----------------------------

.. automethod:: hvac.api.system_backend.Key.read_root_generation_progress
   :noindex:

Examples
````````

.. testcode:: sys_key

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    root_gen_progress = client.sys.read_root_generation_progress()
    print('Root generation "started" status: %s' % root_gen_progress['started'])

Example output:

.. testoutput:: sys_key

    Root generation "started" status: ...


Start Root Token Generation
---------------------------

.. automethod:: hvac.api.system_backend.Key.start_root_token_generation
   :noindex:

Examples
````````

.. testcode:: sys_key

    import hvac
    from tests.utils import get_generate_root_otp

    client = hvac.Client(url='https://127.0.0.1:8200')

    new_otp = get_generate_root_otp()
    start_generate_root_response = client.sys.start_root_token_generation(
        otp=new_otp,
    )
    nonce = start_generate_root_response['nonce']
    print('Nonce for root generation is: %s' % nonce)

Example output:

.. testoutput:: sys_key

    Nonce for root generation is: ...


Cancel Root Generation
----------------------

.. automethod:: hvac.api.system_backend.Key.cancel_root_generation
   :noindex:

Examples
````````

.. testcode:: sys_key

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.cancel_root_generation()


Generate Root
-------------

.. automethod:: hvac.api.system_backend.Key.generate_root
   :noindex:

Examples
````````

.. testsetup:: sys_key_generate_root

    from tests.utils import get_generate_root_otp
    new_otp = get_generate_root_otp()
    start_generate_root_response = client.sys.start_root_token_generation(
        otp=new_otp,
    )
    nonce = start_generate_root_response['nonce']
    key = manager.keys[0]

.. testcode:: sys_key_generate_root

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.generate_root(
        key=key,
        nonce=nonce,
    )


Get Encryption Key Status
-------------------------

.. autoattribute:: hvac.v1.Client.key_status
   :noindex:

Examples
````````

.. testcode:: sys_key

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    print('Encryption key term is: %s' % client.key_status['term'])

Example output:

.. testoutput:: sys_key

    Encryption key term is: 1


Rotate Encryption Key
---------------------

.. automethod:: hvac.api.system_backend.Key.rotate_encryption_key
   :noindex:

Examples
````````

.. testcode:: sys_key

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.rotate_encryption_key()


Read Rekey Progress
-------------------

.. automethod:: hvac.api.system_backend.Key.read_rekey_progress
   :noindex:

Examples
````````

.. testcode:: sys_key

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    print('Rekey "started" status is: %s' % client.sys.read_rekey_progress()['started'])

Example output:

.. testoutput:: sys_key

    Rekey "started" status is: False


Start Rekey
-----------

.. automethod:: hvac.api.system_backend.Key.start_rekey
   :noindex:

Examples
````````

.. testcode:: sys_key

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    rekey_response = client.sys.start_rekey()
    nonce = rekey_response['nonce']
    print('Nonce for rekey is: %s' % nonce)

Example output:

.. testoutput:: sys_key

    Nonce for rekey is: ...


Cancel Rekey
------------

.. automethod:: hvac.api.system_backend.Key.cancel_rekey
   :noindex:

Examples
````````

.. testcode:: sys_key

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.cancel_rekey()


Rekey
-----

.. automethod:: hvac.api.system_backend.Key.rekey
   :noindex:

Examples
````````

.. testsetup:: sys_key_rekey

    keys = manager.keys
    key = keys[0]
    rekey_response = client.sys.start_rekey()
    nonce = rekey_response['nonce']

.. testcode:: sys_key_rekey

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.rekey(
        key=key,
        nonce=nonce,
    )


Rekey Multi
-----------

.. automethod:: hvac.api.system_backend.Key.rekey_multi
   :noindex:

Examples
````````

.. testsetup:: sys_key_rekey_multi

    keys = manager.keys
    key = keys[0]
    rekey_response = client.sys.start_rekey()
    nonce = rekey_response['nonce']

.. testcode:: sys_key_rekey_multi

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.rekey_multi(
        keys,
        nonce=nonce,
    )

Read Rekey Verify Progress
--------------------------

.. automethod:: hvac.api.system_backend.Key.read_rekey_verify_progress
   :noindex:

Examples
````````

.. testsetup:: sys_key_read_rekey_verify_progress

    keys = manager.keys
    key = keys[0]
    rekey_response = client.sys.start_rekey(require_verification=True)
    nonce = rekey_response['nonce']
    rekey_response = client.sys.rekey_multi(keys, nonce=nonce)

.. testcode:: sys_key_read_rekey_verify_progress

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    response = client.sys.read_rekey_verify_progress()

    print(
        'Rekey verify progress is %d out of %d' % (
            response['progress'],
            response['t'],
        )
    )

Example output:

.. testoutput:: sys_key_read_rekey_verify_progress

    Rekey verify progress is 0 out of 3


Cancel Rekey Verify
-------------------

.. automethod:: hvac.api.system_backend.Key.cancel_rekey_verify
   :noindex:

Examples
````````

.. testsetup:: sys_key_cancel_rekey_verify

    keys = manager.keys
    key = keys[0]
    rekey_response = client.sys.start_rekey(require_verification=True)
    nonce = rekey_response['nonce']
    rekey_response = client.sys.rekey_multi(keys, nonce=nonce)

.. testcode:: sys_key_cancel_rekey_verify

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.cancel_rekey_verify()


Rekey Verify
------------

.. automethod:: hvac.api.system_backend.Key.rekey_verify
   :noindex:

Examples
````````

.. testsetup:: sys_key_rekey_verify

    keys = manager.keys
    rekey_response = client.sys.start_rekey(require_verification=True)
    nonce = rekey_response['nonce']
    rekey_response = client.sys.rekey_multi(keys, nonce=nonce)
    verify_nonce = rekey_response['verification_nonce']
    manager.keys = rekey_response['keys']
    key = manager.keys[0]

.. testcode:: sys_key_rekey_verify

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.rekey_verify(
        key,
        nonce=verify_nonce,
    )


Rekey Verify Multi
------------------

.. automethod:: hvac.api.system_backend.Key.rekey_verify_multi
   :noindex:

Examples
````````

.. testsetup:: sys_key_rekey_verify_multi

    keys = manager.keys
    key = keys[0]
    rekey_response = client.sys.start_rekey(require_verification=True)
    nonce = rekey_response['nonce']
    rekey_response = client.sys.rekey_multi(keys, nonce=nonce)
    verify_nonce = rekey_response['verification_nonce']
    manager.keys = rekey_response['keys']
    keys = manager.keys

.. testcode:: sys_key_rekey_verify_multi

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.rekey_verify_multi(
        keys,
        nonce=verify_nonce,
    )



Read Backup Keys
----------------

.. automethod:: hvac.api.system_backend.Key.read_backup_keys
   :noindex:

Examples
````````

.. testsetup:: sys_key_backup_keys

    keys = manager.keys
    key = keys[0]
    pgp_key_path = test_utils.get_config_file_path('pgp_key.asc.b64')
    pgp_key = test_utils.load_config_file(pgp_key_path)
    pgp_keys = [pgp_key]

.. testcode:: sys_key_backup_keys

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    rekey_response = client.sys.start_rekey(
        secret_shares=1,
        secret_threshold=1,
        pgp_keys=pgp_keys,
        backup=True,
    )
    nonce = rekey_response['nonce']

    client.sys.rekey_multi(
        keys,
        nonce=nonce,
    )

    print('Backup keys are: %s' % client.sys.read_backup_keys()['data']['keys'])

Example output:

.. testoutput:: sys_key_backup_keys

    Backup keys are: {'...': [...]}

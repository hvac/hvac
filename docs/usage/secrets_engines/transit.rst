Transit
=======

.. contents::
   :local:
   :depth: 1


.. testsetup:: transit_secret

    client.sys.enable_secrets_engine(
        backend_type='transit',
    )

.. note:: The following helper method is used various of the examples included here.

.. testcode:: transit_secret

    import sys


    def base64ify(bytes_or_str):
        """Helper method to perform base64 encoding across Python 2.7 and Python 3.X"""
        if sys.version_info[0] >= 3 and isinstance(bytes_or_str, str):
            input_bytes = bytes_or_str.encode('utf8')
        else:
            input_bytes = bytes_or_str

        output_bytes = base64.urlsafe_b64encode(input_bytes)
        if sys.version_info[0] >= 3:
            return output_bytes.decode('ascii')
        else:
            return output_bytes

Create Key
----------

.. automethod:: hvac.api.secrets_engines.Transit.create_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.secrets.transit.create_key(name='hvac-key')

Read Key
--------

.. automethod:: hvac.api.secrets_engines.Transit.read_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    read_key_response = client.secrets.transit.read_key(name='hvac-key')
    latest_version = read_key_response['data']['latest_version']
    print('Latest version for key "hvac-key" is: {ver}'.format(ver=latest_version))


List Keys
---------

.. automethod:: hvac.api.secrets_engines.Transit.list_keys
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    list_keys_response = client.secrets.transit.read_key(name='hvac-key')
    keys = list_keys_response['data']['keys']
    print('Currently configured keys: {keys}'.format(keys=keys))


Delete Key
----------

.. automethod:: hvac.api.secrets_engines.Transit.delete_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    client.secrets.transit.delete_key(name='hvac-key')


Update Key Configuration
------------------------

.. automethod:: hvac.api.secrets_engines.Transit.update_key_configuration
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    # allow key "hvac-key" to be exported in subsequent requests
    client.secrets.transit.update_key_configuration(
        name='hvac-key',
        exportable=True,
    )


Rotate Key
----------

.. automethod:: hvac.api.secrets_engines.Transit.rotate_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    client.secrets.transit.rotate_key(name='hvac-key')

Export Key
----------

.. automethod:: hvac.api.secrets_engines.Transit.export_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    export_key_response = client.secrets.transit.export_key(name='hvac-key')

    first_key = export_key_response['keys']['1']

Encrypt Data
------------

.. automethod:: hvac.api.secrets_engines.Transit.decrypt_data
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import base64
    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    encrypt_data_response = client.secrets.transit.encrypt_data(
        name='hvac-key',
        plaintext=base64.urlsafe_b64encode('hi its me hvac'.encode()).decode('ascii'),
    )
    ciphertext = encrypt_data_response['data']['ciphertext']
    print('Encrypted plaintext ciphertext is: {cipher}'.format(cipher=ciphertext))


Decrypt Data
------------

.. automethod:: hvac.api.secrets_engines.Transit.decrypt_data
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    decrypt_data_response = client.secrets.transit.decrypt_data(
        name='hvac-key',
        ciphertext=ciphertext,
    )
    plaintext = decrypt_data_response['data']['plaintext']
    print('Decrypted plaintext is: {text}'.format(text=plaintext))


Rewrap Data
-----------

.. automethod:: hvac.api.secrets_engines.Transit.rewrap_data
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    encrypt_data_response = client.secrets.transit.rewrap_data(
        name='hvac-key',
        ciphertext=ciphertext,
    )
    rewrapped_ciphertext = encrypt_data_response['data']['ciphertext']
    print('Rewrapped ciphertext is: {cipher}'.format(cipher=rewrapped_ciphertext))


Generate Data Key
-----------------

.. automethod:: hvac.api.secrets_engines.Transit.generate_data_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    gen_key_response = client.secrets.transit.generate_data_key(name='hvac-key')
    ciphertext = gen_data_key_response['data']
    print('Generated data key is: {cipher}'.format(cipher=ciphertext))


Generate Random Bytes
---------------------

.. automethod:: hvac.api.secrets_engines.Transit.generate_random_bytes
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    gen_bytes_response = client.secrets.transit.generate_random_bytes(n_bytes=32)
    random_bytes = gen_bytes_response['data']['random_bytes']
    print('Here are some random bytes: {bytes}'.format(bytes=random_bytes))



Hash Data
---------

.. automethod:: hvac.api.secrets_engines.Transit.hash_data
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    hash_data_response = client.secrets.transit.hash_data(
        name='hvac-key',
        hash_input=base64.urlsafe_b64encode('hi its me hvac').decode('ascii'),
    )
    sum = hash_data_response['data']['sum']
    print('Hashed data is: {sum}'.format(sum=sum))


Generate Hmac
-------------

.. automethod:: hvac.api.secrets_engines.Transit.generate_hmac
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    generate_hmac_response = client.secrets.transit.hash_data(
        name='hvac-key',
        hash_input=base64.urlsafe_b64encode('hi its me hvac').decode('ascii'),
    )
    hmac = generate_hmac_response['data']['sum']
    print('HMAC'd data is: {hmac}'.format(hmac=hmac))


Sign Data
---------

.. automethod:: hvac.api.secrets_engines.Transit.sign_data
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    sign_data_response = client.secrets.transit.sign_data(
        name='hvac-key',
        hash_input=base64.urlsafe_b64encode('hi its me hvac').decode('ascii'),
    )
    signature = sign_data_response['data']['signature']
    print('Signature is: {signature}'.format(signature=signature))


Verify Signed Data
------------------

.. automethod:: hvac.api.secrets_engines.Transit.verify_signed_data
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    verify_signed_data_response = client.secrets.transit.verify_signed_data(
        name='hvac-key',
        hash_input=base64.urlsafe_b64encode('hi its me hvac').decode('ascii'),
    )
    valid = verify_signed_data_response['data']['valid']
    print('Signature is valid?: {valid}'.format(valid=valid))


Backup Key
----------

.. automethod:: hvac.api.secrets_engines.Transit.backup_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    backup_key_response = client.secrets.transit.backup_key(
        name='hvac-key',
        mount_point=TEST_MOUNT_POINT,
    )
    backed_up_key = backup_key_response['data']['backup']

Restore Key
-----------

.. automethod:: hvac.api.secrets_engines.Transit.restore_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    client.secrets.transit.restore_key(backup=backed_up_key)


Trim Key
--------

.. automethod:: hvac.api.secrets_engines.Transit.trim_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.secrets.transit.trim_key(
        name='hvac-key',
        min_version=3,
    )

.. testcleanup:: transit_secret

    client.sys.disable_secrets_engine('transit')

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
        if isinstance(bytes_or_str, str):
            input_bytes = bytes_or_str.encode('utf8')
        else:
            input_bytes = bytes_or_str

        output_bytes = base64.urlsafe_b64encode(input_bytes)
        return output_bytes.decode('ascii')

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

Example output:

.. testoutput:: transit_secret

    Latest version for key "hvac-key" is: 1


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

Example output:

.. testoutput:: transit_secret

    Currently configured keys: {'1': ...}


Delete Key
----------

.. automethod:: hvac.api.secrets_engines.Transit.delete_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    key_name = 'gonna-delete-this-key'

    client.secrets.transit.create_key(
        name=key_name,
    )

    # Update key subsequently to allow deletion...
    client.secrets.transit.update_key_configuration(
        name=key_name,
        deletion_allowed=True,
    )

    # Finally, delete the key
    client.secrets.transit.delete_key(name=key_name)


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
    export_key_response = client.secrets.transit.export_key(
        name='hvac-key',
        key_type='hmac-key',
    )

    print('Exported keys: %s' % export_key_response['data']['keys'])

Example output:

.. testoutput:: transit_secret

    Exported keys: {...}

Encrypt Data
------------

.. automethod:: hvac.api.secrets_engines.Transit.encrypt_data
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import base64
    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    encrypt_data_response = client.secrets.transit.encrypt_data(
        name='hvac-key',
        plaintext=base64ify('hi its me hvac'.encode()),
    )
    ciphertext = encrypt_data_response['data']['ciphertext']
    print('Encrypted plaintext ciphertext is: {cipher}'.format(cipher=ciphertext))

Example output:

.. testoutput:: transit_secret

    Encrypted plaintext ciphertext is: vault:...


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

Example output:

.. testoutput:: transit_secret

    Decrypted plaintext is: ...


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

Example output:

.. testoutput:: transit_secret

    Rewrapped ciphertext is: vault:...


Generate Data Key
-----------------

.. automethod:: hvac.api.secrets_engines.Transit.generate_data_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    gen_key_response = client.secrets.transit.generate_data_key(
        name='hvac-key',
        key_type='plaintext',
    )
    ciphertext = gen_key_response['data']['ciphertext']
    print('Generated data key ciphertext is: {cipher}'.format(cipher=ciphertext))

Example output:

.. testoutput:: transit_secret


    Generated data key ciphertext is: vault:...

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

Example output:

.. testoutput:: transit_secret

    Here are some random bytes: ...


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
        hash_input=base64ify('hi its me hvac'),
        algorithm='sha2-256',
    )
    sum = hash_data_response['data']['sum']
    print('Hashed data is: {sum}'.format(sum=sum))

Example output:

.. testoutput:: transit_secret

    Hashed data is: ...


Generate Hmac
-------------

.. automethod:: hvac.api.secrets_engines.Transit.generate_hmac
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    generate_hmac_response = client.secrets.transit.generate_hmac(
        name='hvac-key',
        hash_input=base64ify('hi its me hvac'),
        algorithm='sha2-256',
    )
    hmac = generate_hmac_response['data']
    print("HMAC'd data is: {hmac}".format(hmac=hmac))

Example output:

.. testoutput:: transit_secret

    HMAC'd data is: {'hmac': 'vault:...'}


Sign Data
---------

.. automethod:: hvac.api.secrets_engines.Transit.sign_data
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    key_name = 'hvac-signing-key'

    # Note: some key types do no support signing...
    # E.g., "key type aes256-gcm96 does not support verification"
    client.secrets.transit.create_key(
        name=key_name,
        key_type='ed25519',
    )

    sign_data_response = client.secrets.transit.sign_data(
        name=key_name,
        hash_input=base64ify('hi its me hvac'),
    )
    signature = sign_data_response['data']['signature']
    print('Signature is: {signature}'.format(signature=signature))

Example output:

.. testoutput:: transit_secret

    Signature is: vault:...


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
        name='hvac-signing-key',
        hash_input=base64ify('hi its me hvac'),
        signature=signature,
    )
    valid = verify_signed_data_response['data']['valid']
    print('Signature is valid?: {valid}'.format(valid=valid))

Example output:

.. testoutput:: transit_secret

    Signature is valid?: True


Backup Key
----------

.. automethod:: hvac.api.secrets_engines.Transit.backup_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    key_name = 'hvac-key'

    # Update the key configuration to allow exporting
    client.secrets.transit.update_key_configuration(
        name=key_name,
        exportable=True,
        allow_plaintext_backup=True,
    )

    backup_key_response = client.secrets.transit.backup_key(
        name=key_name,
    )

    backed_up_key = backup_key_response['data']['backup']
    print('Backed up key: %s' % backed_up_key)

Example output:

.. testoutput:: transit_secret

    Backed up key: ...

Restore Key
-----------

.. automethod:: hvac.api.secrets_engines.Transit.restore_key
   :noindex:

Examples
````````

.. testcode:: transit_secret

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')

    client.secrets.transit.update_key_configuration(
        name=key_name,
        deletion_allowed=True,
    )
    delete_resp = client.secrets.transit.delete_key(name=key_name)

    # Restore a key after deletion
    client.secrets.transit.restore_key(backup=backed_up_key)


Trim Key
--------

.. automethod:: hvac.api.secrets_engines.Transit.trim_key
   :noindex:

Examples
````````

.. note:: Transit key trimming was added for Vault versions >=0.11.4.

.. testcode:: transit_secret
    :skipif: test_utils.vault_version_lt('0.11.4')

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    key_name = 'hvac-key'

    for _ in range(0, 10):
        # Rotate the key a bunch...
        client.secrets.transit.rotate_key(
            name=key_name,
        )

    # Set a minimum encryption version
    client.secrets.transit.update_key_configuration(
        name=key_name,
        min_decryption_version=3,
        min_encryption_version=5,
    )

    # Trim any unneeded versions remaining of the key...
    client.secrets.transit.trim_key(
        name='hvac-key',
        min_version=3,
    )

.. testcleanup:: transit_secret

    client.sys.disable_secrets_engine('transit')

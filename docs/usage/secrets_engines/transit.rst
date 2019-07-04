Transit
=======

Create Key
----------

:py:meth:`hvac.api.secrets_engines.Transit.create_key`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.transit.create_key(name='hvac-key')

Read Key
--------

:py:meth:`hvac.api.secrets_engines.Transit.read_key`

.. code:: python

	import hvac
	client = hvac.Client()

	read_key_response = client.secrets.transit.read_key(name='hvac-key')
	latest_version = read_key_response['data']['latest_version']
	print('Latest version for key "hvac-key" is: {ver}'.format(ver=latest_version))


List Keys
---------

:py:meth:`hvac.api.secrets_engines.Transit.list_keys`

.. code:: python

	import hvac
	client = hvac.Client()

	list_keys_response = client.secrets.transit.read_key(name='hvac-key')
	keys = list_keys_response['data']['keys']
	print('Currently configured keys: {keys}'.format(keys=keys))


Delete Key
----------

:py:meth:`hvac.api.secrets_engines.Transit.delete_key`

.. code:: python

	import hvac
	client = hvac.Client()
	client.secrets.transit.delete_key(name='hvac-key')


Update Key Configuration
------------------------

:py:meth:`hvac.api.secrets_engines.Transit.update_key_configuration`

.. code:: python

	import hvac
	client = hvac.Client()

	# allow key "hvac-key" to be exported in subsequent requests
	client.secrets.transit.update_key_configuration(
		name='hvac-key',
		exportable=True,
	)


Rotate Key
----------

:py:meth:`hvac.api.secrets_engines.Transit.rotate_key`

.. code:: python

	import hvac
	client = hvac.Client()
	client.secrets.transit.rotate_key(name='hvac-key')

Export Key
----------

:py:meth:`hvac.api.secrets_engines.Transit.encrypt_key`

.. code:: python

	import hvac
	client = hvac.Client()
	export_key_response = client.secrets.transit.export_key(name='hvac-key')

	first_key = export_key_response['keys']['1']

Encrypt Data
------------

:py:meth:`hvac.api.secrets_engines.Transit.decrypt_data`

.. code:: python

	import base64
	import hvac
	client = hvac.Client()

	encrypt_data_response = client.secrets.transit.encrypt_data(
		name='hvac-key',
		plaintext=base64.urlsafe_b64encode('hi its me hvac'.encode()).decode('ascii'),
	)
	ciphertext = encrypt_data_response['data']['ciphertext']
	print('Encrypted plaintext ciphertext is: {cipher}'.format(cipher=ciphertext))


Decrypt Data
------------

:py:meth:`hvac.api.secrets_engines.Transit.decrypt_data`

.. code:: python

	import hvac
	client = hvac.Client()
	
	decrypt_data_response = client.secrets.transit.decrypt_data(
		name='hvac-key',
		ciphertext=ciphertext,
	)
	plaintext = decrypt_data_response['data']['plaintext']
	print('Decrypted plaintext is: {text}'.format(text=plaintext))


Rewrap Data
-----------

:py:meth:`hvac.api.secrets_engines.Transit.rewrap_data`

.. code:: python

	import hvac
	client = hvac.Client()

	encrypt_data_response = client.secrets.transit.rewrap_data(
		name='hvac-key',
		ciphertext=ciphertext,
	)
	rewrapped_ciphertext = encrypt_data_response['data']['ciphertext']
	print('Rewrapped ciphertext is: {cipher}'.format(cipher=rewrapped_ciphertext))


Generate Data Key
-----------------

:py:meth:`hvac.api.secrets_engines.Transit.generate_data_key`

.. code:: python

	import hvac
	client = hvac.Client()
	gen_key_response = client.secrets.transit.generate_data_key(name='hvac-key')
	ciphertext = gen_data_key_response['data']
	print('Generated data key is: {cipher}'.format(cipher=ciphertext))


Generate Random Bytes
---------------------

:py:meth:`hvac.api.secrets_engines.Transit.generate_random_bytes`

.. code:: python

	import hvac
	client = hvac.Client()

	gen_bytes_response = client.secrets.transit.generate_random_bytes(n_bytes=32)
	random_bytes = gen_bytes_response['data']['random_bytes']
	print('Here are some random bytes: {bytes}'.format(bytes=random_bytes))



Hash Data
---------

:py:meth:`hvac.api.secrets_engines.Transit.hash_data`

.. code:: python

	import hvac
	client = hvac.Client()

	hash_data_response = client.secrets.transit.hash_data(
		name='hvac-key',
		hash_input=base64.urlsafe_b64encode('hi its me hvac').decode('ascii'),
	)
	sum = hash_data_response['data']['sum']
	print('Hashed data is: {sum}'.format(sum=sum))


Generate Hmac
-------------

:py:meth:`hvac.api.secrets_engines.Transit.generate_hmac`

.. code:: python

	import hvac
	client = hvac.Client()

	generate_hmac_response = client.secrets.transit.hash_data(
		name='hvac-key',
		hash_input=base64.urlsafe_b64encode('hi its me hvac').decode('ascii'),
	)
	hmac = generate_hmac_response['data']['sum']
	print('HMAC'd data is: {hmac}'.format(hmac=hmac))


Sign Data
---------

:py:meth:`hvac.api.secrets_engines.Transit.sign_data`

.. code:: python

	import hvac
	client = hvac.Client()

	sign_data_response = client.secrets.transit.sign_data(
		name='hvac-key',
		hash_input=base64.urlsafe_b64encode('hi its me hvac').decode('ascii'),
	)
	signature = sign_data_response['data']['signature']
	print('Signature is: {signature}'.format(signature=signature))


Verify Signed Data
------------------

:py:meth:`hvac.api.secrets_engines.Transit.verify_signed_data`

.. code:: python

	import hvac
	client = hvac.Client()

	verify_signed_data_response = client.secrets.transit.verify_signed_data(
		name='hvac-key',
		hash_input=base64.urlsafe_b64encode('hi its me hvac').decode('ascii'),
	)
	valid = verify_signed_data_response['data']['valid']
	print('Signature is valid?: {valid}'.format(valid=valid))


Backup Key
----------

:py:meth:`hvac.api.secrets_engines.Transit.backup_key`

.. code:: python

	import hvac
	client = hvac.Client()

	backup_key_response = client.secrets.transit.backup_key(
		name='hvac-key',
		mount_point=TEST_MOUNT_POINT,
	)
	backed_up_key = backup_key_response['data']['backup']

Restore Key
-----------

:py:meth:`hvac.api.secrets_engines.Transit.restore_key`

.. code:: python

	import hvac
	client = hvac.Client()
	client.secrets.transit.restore_key(backup=backed_up_key)


Trim Key
--------

:py:meth:`hvac.api.secrets_engines.Transit.trim_key`

.. code:: python

	import hvac
	client = hvac.Client()

	client.secrets.transit.trim_key(
		name='hvac-key',
		min_version=3,
	)

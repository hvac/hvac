Key
===

Read Root Generation Progress
-----------------------------

:py:meth:`hvac.api.system_backend.Key.read_root_generation_progress`

.. code:: python

	import hvac
	client = hvac.Client()

	root_gen_progress = client.sys.read_root_generation_progress()
	print('Root generation "started" status: %s' % root_gen_progress['started'])


Start Root Token Generation
---------------------------

:py:meth:`hvac.api.system_backend.Key.start_root_token_generation`

.. code:: python

	import hvac
	client = hvac.Client()

	new_otp = 'RSMGkAqBH5WnVLrDTbZ+UQ=='
	start_generate_root_response = client.sys.start_root_token_generation(
        otp=new_otp,
    )
	print('Nonce for root generation is: %s' % start_generate_root_response['nonce'])


Cancel Root Generation
----------------------

:py:meth:`hvac.api.system_backend.Key.cancel_root_generation`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.cancel_root_generation()


Generate Root
-------------

:py:meth:`hvac.api.system_backend.Key.generate_root`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.generate_root(
		key=key,
		nonce=nonce,
	)


Get Encryption Key Status
-------------------------

:py:meth:`hvac.api.system_backend.Key.get_encryption_key_status`

.. code:: python

	import hvac
	client = hvac.Client()

	print('Encryption key term is: %s' % client.sys.key_status['term'])


Rotate Encryption Key
---------------------

:py:meth:`hvac.api.system_backend.Key.rotate_encryption_key`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.rotate_encryption_key()


Read Rekey Progress
-------------------

:py:meth:`hvac.api.system_backend.Key.read_rekey_progress`

.. code:: python

	import hvac
	client = hvac.Client()

	print('Rekey "started" status is: %s' % client.sys.read_rekey_progress()['started'])


Start Rekey
-----------

:py:meth:`hvac.api.system_backend.Key.start_rekey`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.start_rekey()


Cancel Rekey
------------

:py:meth:`hvac.api.system_backend.Key.cancel_rekey`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.cancel_rekey()


Rekey
-----

:py:meth:`hvac.api.system_backend.Key.rekey`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.rekey(
		key=key,
		nonce=nonce,
		recovery_key=recovery_key,
	)


Rekey Multi
-----------

:py:meth:`hvac.api.system_backend.Key.rekey_multi`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.rekey_multi(keys, nonce=nonce)


Read Backup Keys
----------------

:py:meth:`hvac.api.system_backend.Key.read_backup_keys`

.. code:: python

	import hvac
	client = hvac.Client()

	print('Backup keys are: %s' % client.sys.read_backup_keys()['keys'])


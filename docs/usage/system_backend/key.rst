Key
===

Read Root Generation Progress
-----------------------------

:py:meth:`hvac.api.system_backend.key.read_root_generation_progress`

.. code:: python

	import hvac
	client = hvac.Client()

	root_gen_progress = client.sys.read_root_generation_progress()
	print('Root generation "started" status: %s' % root_gen_progress['started'])


Start Root Token Generation
---------------------------

:py:meth:`hvac.api.system_backend.key.start_root_token_generation`

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

:py:meth:`hvac.api.system_backend.key.cancel_root_generation`

.. code:: python

	import hvac
	client = hvac.Client()


Generate Root
-------------

:py:meth:`hvac.api.system_backend.key.generate_root`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.cancel_root_generation()


Get Encryption Key Status
-------------------------

:py:meth:`hvac.api.system_backend.key.get_encryption_key_status`

.. code:: python

	import hvac
	client = hvac.Client()


Rotate Encryption Key
---------------------

:py:meth:`hvac.api.system_backend.key.rotate_encryption_key`

.. code:: python

	import hvac
	client = hvac.Client()


Read Rekey Progress
-------------------

:py:meth:`hvac.api.system_backend.key.read_rekey_progress`

.. code:: python

	import hvac
	client = hvac.Client()


Start Rekey
-----------

:py:meth:`hvac.api.system_backend.key.start_rekey`

.. code:: python

	import hvac
	client = hvac.Client()


Cancel Rekey
------------

:py:meth:`hvac.api.system_backend.key.cancel_rekey`

.. code:: python

	import hvac
	client = hvac.Client()


Rekey
-----

:py:meth:`hvac.api.system_backend.key.rekey`

.. code:: python

	import hvac
	client = hvac.Client()


Rekey Multi
-----------

:py:meth:`hvac.api.system_backend.key.rekey_multi`

.. code:: python

	import hvac
	client = hvac.Client()


Read Backup Key
---------------

:py:meth:`hvac.api.system_backend.key.read_backup_key`

.. code:: python

	import hvac
	client = hvac.Client()



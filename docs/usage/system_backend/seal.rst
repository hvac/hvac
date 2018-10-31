Seal
====


Seal Status
-----------

:py:meth:`hvac.api.system_backend.Seal.seal_status`

.. code:: python

	import hvac
	client = hvac.Client()

	print('Is Vault sealed: %s' % client.sys.seal_status['sealed'])


Is Sealed
---------

:py:meth:`hvac.api.system_backend.Seal.is_sealed`

.. code:: python

	import hvac
	client = hvac.Client()

	print('Is Vault sealed: %s' % client.sys.is_sealed())


Read Seal Status
----------------

:py:meth:`hvac.api.system_backend.Seal.read_status`

.. code:: python

	import hvac
	client = hvac.Client()

	print('Is Vault sealed: %s' % client.sys.read_seal_status()['sealed'])


Seal
----

:py:meth:`hvac.api.system_backend.Seal.read_status`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.seal()


Submit Unseal Key
-----------------

:py:meth:`hvac.api.system_backend.Seal.submit_unseal_key`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.submit_unseal_key(key=key)


Submit Unseal Keys
------------------

:py:meth:`hvac.api.system_backend.Seal.read_status`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.submit_unseal_keys(keys=keys)




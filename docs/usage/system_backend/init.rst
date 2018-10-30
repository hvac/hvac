Init
====


.. code:: python

	methods = client.sys.list_auth_methods()

	client.sys.enable_auth_method('userpass', path='customuserpass')
	client.sys.disable_auth_method('github')

Read Status
-----------

:py:meth:`hvac.api.system_backend.Init.read_init_status`

.. code:: python

	import hvac
	client = hvac.Client()

	read_response = client.sys.read_init_status()
	print('Vault initialize status: %s' % read_response['initialized'])


Is Initialized
--------------

:py:meth:`hvac.api.system_backend.Init.is_initialized`

.. code:: python

	import hvac
	client = hvac.Client()

	print('Vault initialize status: %s' % client.sys.is_initialized())


Initialize
----------

:py:meth:`hvac.api.system_backend.Init.initialize`

.. code:: python

	import hvac
	client = hvac.Client()

	init_result = client.sys.initialize()

	root_token = init_result['root_token']
	unseal_keys = init_result['keys']


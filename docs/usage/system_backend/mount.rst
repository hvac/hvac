Mount
=====


Manipulate secret backends
--------------------------

.. code:: python

	backends = client.sys.list_secret_backends()['data']

	client.sys.enable_secrets_engine('aws', path='aws-us-east-1')
	client.sys.disable_secrets_engine('mysql')

	client.sys.tune_mount_configuration(path='test', default_lease_ttl='3600s', max_lease_ttl='8600s')
	client.sys.read_mount_configuration(path='test')

	client.sys.move_backend('aws-us-east-1', 'aws-east')


List Mounted Secrets Engines
----------------------------

:py:meth:`hvac.api.system_backend.Mount.list_mounted_secrets_engines`

.. code:: python

	import hvac
	client = hvac.Client()

	secrets_engines_list = client.sys.list_mounted_secrets_engines()['data']
	print('The following secrets engines are mounted: %s' % secret_engines_list.keys())


Enable Secrets Engine
---------------------

:py:meth:`hvac.api.system_backend.Mount.enable_secrets_engine`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.enable_secrets_engine(
		backend_type='github',
		path='hvac-github',
	)


Disable Secrets Engine
----------------------

:py:meth:`hvac.api.system_backend.Mount.disable_secrets_engine`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.disable_secrets_engine(
		path='hvac-github',
	)


Read Mount Configuration
------------------------

:py:meth:`hvac.api.system_backend.Mount.read_mount_configuration`

.. code:: python

	import hvac
	client = hvac.Client()

	secret_backend_tuning = client.sys.read_mount_configuration(path='hvac-github')
	print('The max lease TTL for the "hvac-github" backend is: {max_lease_ttl}'.format(
		max_lease_ttl=secret_backend_tuning['data']['max_lease_ttl'],
	 ))


Tune Mount Configuration
------------------------

:py:meth:`hvac.api.system_backend.Mount.tune_mount_configuration`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.tune_mount_configuration(
		path='hvac-github',
		default_lease_ttl='3600s',
		max_lease_ttl='8600s',
	)


Move Backend
------------

:py:meth:`hvac.api.system_backend.Mount.move_backend`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.move_backend(
		from_path='hvac-github',
		to_path='github-hvac',
	)

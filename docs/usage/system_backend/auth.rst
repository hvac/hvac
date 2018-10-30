Auth
====


.. code:: python

	methods = client.sys.list_auth_methods()

	client.sys.enable_auth_method('userpass', path='customuserpass')
	client.sys.disable_auth_method('github')

List Auth Methods
-----------------

:py:meth:`hvac.api.system_backend.Auth.list_auth_methods`

.. code:: python

	import hvac
	client = hvac.Client()

	auth_methods = self.client.sys.list_auth_methods()
	print('The following auth methods are enabled: {auth_methods_list}'.format(
		auth_methods_list=auth_methods['data'].keys(),
	)


Enable Auth Method
------------------

:py:meth:`hvac.api.system_backend.Auth.enable_auth_method`

.. code:: python

	import hvac
	client = hvac.Client()

	self.client.sys.enable_auth_method(
		method_type='github',
		path='hvac-github',
	)


Disable Auth Method
-------------------

:py:meth:`hvac.api.system_backend.Auth.disable_auth_method`

.. code:: python

	import hvac
	client = hvac.Client()

	self.client.sys.disable_auth_method(
		path='hvac-github',
	)


Read Auth Method Tuning
-----------------------

:py:meth:`hvac.api.system_backend.Auth.read_auth_method_tuning`

.. code:: python

	import hvac
	client = hvac.Client()
	response = self.client.sys.read_auth_method_tuning(
		path='github-hvac',
		description='The Github auth method for hvac users',
	)

	print('The max lease TTL for the auth method under path "github-hvac" is: {max_ttl}'.format(
		max_ttl=response['data']['max_lease_ttl'],
	)


Tune Auth Method
----------------

:py:meth:`hvac.api.system_backend.Auth.tune_auth_method`

.. code:: python

	import hvac
	client = hvac.Client()

	self.client.sys.tune_auth_method(
		path=self.TEST_AUTH_METHOD_PATH,
		description='The Github auth method for hvac users',
	)




Azure
=====

The :py:class:`hvac.api.azure.Azure` instance under the :py:attr:`Client class's azure attribute<hvac.v1.Client.azure>` is a wrapper to expose either the :py:class:`Azure auth method class<hvac.api.auth.Azure>` or the :py:class:`Azure secret engine class<hvac.api.secrets_engines.Azure>`. The instances of these classes are under the :py:attr:`auth<hvac.v1.api.azure.Azure.auth>` and :py:attr:`secret<hvac.v1.api.azure.Azure.secret>` attributes respectively.

Auth Method
-----------

:ref:`azure-auth-method`.

Calling a Azure auth method:

.. code:: python

	import hvac

	client = hvac.Client()
	client.azure.auth.configure(
		# [...]
	)
	client.azure.auth.create_role(
		name='some-azure-role-name',
	)
	client.azure.auth.login(
		role='some-azure-role-name',
		jwt='a JWT from Azure MST...',
	)


Secret Engine
-------------

:ref:`azure-secret-engine`.

Calling a Azure secret engine method:

.. code:: python

	import hvac
	from azure.common.credentials import ServicePrincipalCredentials

	client = hvac.Client()
	client.azure.secret.configure(
		# [...]
	)
	client.azure.auth.create_or_update_role(
		name='some-azure-role-name',
	)
	azure_creds = client.azure.auth.generate_credentials(
		name='some-azure-role-name',
	)
	azure_spc = ServicePrincipalCredentials(
		client_id=azure_creds['client_id'],
		secret=azure_creds['client_secret'],
		tenant=TENANT_ID,
	)

	# [...]

GCP
===

The :py:class:`hvac.api.gcp.Gcp` instance under the :py:attr:`Client class's gcp attribute<hvac.v1.Client.gcp>` is a wrapper to expose either the :py:class:`GCP auth method class<hvac.api.auth.Gcp>` or the :py:class:`GCP secret engine class<hvac.api.secrets_engines.Gcp>`. The instances of these classes are under the :py:meth:`auth<hvac.api.gcp.Gcp.auth>` and :py:meth:`secret<hvac.api.gcp.Gcp.secret>` attributes respectively.

Auth Method
-----------

.. note::

	Additional examples available at: :ref:`GCP Auth Method Usage<gcp-auth-method>`.

Calling a GCP auth method:

.. code:: python

	import hvac

	client = hvac.Client()
	client.gcp.auth.configure(
		credentials='some signed JSON web token for the Vault server...'
	)
	client.gcp.auth.create_role(
		name='some-gcp-role-name',
		role_type='iam',
		project_id='some-gcp-project-id',
		bound_service_accounts=['*'],
	)
	client.gcp.auth.login(
		role='some-gcp-role-name',
		jwt='some signed JSON web token...',
	)


Secret Engine
-------------

.. warning::

	This feature not currently implemented.

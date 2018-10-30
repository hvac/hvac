Lease
=====


Read Lease
----------

:py:meth:`hvac.api.system_backend.lease.read_lease`

.. code:: python

	import hvac
	client = hvac.Client()

	read_lease_resp = client.sys.read_lease(
		lease_id=lease_id,
	)

	print('Current expire time for lease ID {id} is: {expires}'.format(
		id=lease_id,
		expires=read_lease_resp['data']['expire_time'],
	)


List Leases
-----------

:py:meth:`hvac.api.system_backend.lease.list_leases`

.. code:: python

	import hvac
	client = hvac.Client()

	list_leases_response = client.sys.list_leases(
		prefix='pki',
	)
	print('The follow lease keys are active under the "pki" prefix: %s' % list_leases_response['data']['keys'])


Renew Lease
-----------

:py:meth:`hvac.api.system_backend.lease.renew_lease`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.renew_lease(
		lease_id=lease_id,
		increment=500,
	)


Revoke Lease
------------

:py:meth:`hvac.api.system_backend.lease.revoke_lease`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.revoke_lease(
		lease_id=lease_id,
	)


Revoke Prefix
-------------

:py:meth:`hvac.api.system_backend.lease.revoke_prefix`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.revoke_prefix(
		prefix='pki',
	)


Revoke Force
------------

:py:meth:`hvac.api.system_backend.lease.revoke_force`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.revoke_force(
		lease_id=lease_id,
	)




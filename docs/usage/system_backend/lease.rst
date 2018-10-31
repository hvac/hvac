Lease
=====



View and Manage Leases
----------------------

Read a lease:

.. versionadded:: 0.6.2

.. code-block:: python

	>>> client.read_lease(lease_id='pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f')
	{'lease_id': '', 'warnings': None, 'wrap_info': None, 'auth': None, 'lease_duration': 0, 'request_id': 'a08768dc-b14e-5e2d-f291-4702056f8d4e', 'data': {'last_renewal': None, 'ttl': 259145, 'expire_time': '2018-07-19T06:20:02.000046424-05:00', 'id': 'pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f', 'renewable': False, 'issue_time': '2018-07-16T06:20:02.918474523-05:00'}, 'renewable': False}

Renewing a lease:

.. code-block:: python

	>>> client.sys.renew_lease(lease_id='pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f')
	{'lease_id': 'pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f', 'lease_duration': 2764790, 'renewable': True}

Revoking a lease:

.. code-block:: python

	>>> client.sys.revoke_lease(lease_id='pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f')

Read Lease
----------

:py:meth:`hvac.api.system_backend.Lease.read_lease`

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

:py:meth:`hvac.api.system_backend.Lease.list_leases`

.. code:: python

	import hvac
	client = hvac.Client()

	list_leases_response = client.sys.list_leases(
		prefix='pki',
	)
	print('The follow lease keys are active under the "pki" prefix: %s' % list_leases_response['data']['keys'])


Renew Lease
-----------

:py:meth:`hvac.api.system_backend.Lease.renew_lease`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.renew_lease(
		lease_id=lease_id,
		increment=500,
	)


Revoke Lease
------------

:py:meth:`hvac.api.system_backend.Lease.revoke_lease`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.revoke_lease(
		lease_id=lease_id,
	)


Revoke Prefix
-------------

:py:meth:`hvac.api.system_backend.Lease.revoke_prefix`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.revoke_prefix(
		prefix='pki',
	)


Revoke Force
------------

:py:meth:`hvac.api.system_backend.Lease.revoke_force`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.revoke_force(
		lease_id=lease_id,
	)




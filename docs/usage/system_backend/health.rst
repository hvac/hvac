Health
======


Read Status
-----------

:py:meth:`hvac.api.system_backend.Health.read_health_status`

.. code:: python

	import hvac
	client = hvac.Client()

	status = self.client.sys.read_health_status()
	print('Vault initialization status is: %s' % status['initialized'])

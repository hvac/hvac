Leader
======


Read Leader Status
------------------

:py:meth:`hvac.api.system_backend.Leader.read_leader_status`

.. code:: python

	import hvac
	client = hvac.Client()

	status = self.client.sys.read_leader_status()
	print('HA status is: %s' % status['ha_enabled'])

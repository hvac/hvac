Audit
=====


.. code:: python

	audit_devices = client.list_enabled_audit_devices()

	options = {
		'path': '/tmp/vault.log',
		'log_raw': True,
	}

	client.enable_audit_device('file', options=options, path='somefile')
	client.disable_audit_backend('oldfile')


List Enabled Audit Devices
--------------------------

:py:meth:`hvac.api.system_backend.Audit.list_enabled_audit_devices`

.. code:: python

	import hvac
	client = hvac.Client()

	enabled_audit_devices = self.client.sys.list_enabled_audit_devices()
	print('The following audit devices are enabled: {audit_devices_list}'.format(
		audit_devices_list=enabled_audit_devices['data'].keys(),
	)

Enable Audit Device
-------------------

:py:meth:`hvac.api.system_backend.Audit.enable_audit_device`

.. code:: python

	import hvac
	client = hvac.Client()

	options = {
		'path': '/tmp/vault.audit.log'
	}

	self.client.sys.enable_audit_device(
		device_type='file',
		options=options,
		path='tmp-file-audit',
	)


Disable Audit Device
--------------------

:py:meth:`hvac.api.system_backend.Audit.disable_audit_device`

.. code:: python

	import hvac
	client = hvac.Client()

	self.client.sys.disable_audit_device(
		path='tmp-file-audit',
	)


Calculate Hash
--------------

:py:meth:`hvac.api.system_backend.Audit.calculate_hash`

.. code:: python

	import hvac
	client = hvac.Client()

	input_to_hash = input()

	audit_hash = self.client.sys.calculate_hash(
		path='tmp-file-audit',
		input_to_hash=input_to_hash,
	)

	print('The hash for the provided input is: %s' % audit_hash['data']['hash'])

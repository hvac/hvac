Audit
=====

.. contents::
   :local:
   :depth: 1

Examples
--------

.. testcode:: sys_audit

    audit_devices = client.sys.list_enabled_audit_devices()

    options = {
        'path': '/tmp/vault.log',
        'log_raw': True,
    }

    client.sys.enable_audit_device('file', options=options, path='somefile')
    client.sys.disable_audit_device('oldfile')


List Enabled Audit Devices
--------------------------

.. automethod:: hvac.api.system_backend.Audit.list_enabled_audit_devices
   :noindex:

Examples
````````

.. testcode:: sys_audit

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    enabled_audit_devices = client.sys.list_enabled_audit_devices()
    print('The following audit devices are enabled: {audit_devices_list}'.format(
        audit_devices_list=', '.join(enabled_audit_devices['data'].keys()),
    ))

Example output:

.. testoutput:: sys_audit

    The following audit devices are enabled: somefile/

Enable Audit Device
-------------------

.. automethod:: hvac.api.system_backend.Audit.enable_audit_device
   :noindex:

Examples
````````

.. testcode:: sys_audit

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    options = {
        'path': '/tmp/vault.audit.log'
    }

    client.sys.enable_audit_device(
        device_type='file',
        options=options,
        path='tmp-file-audit',
    )


Disable Audit Device
--------------------

.. automethod:: hvac.api.system_backend.Audit.disable_audit_device
   :noindex:

Examples
````````

.. testcode:: sys_audit

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.disable_audit_device(
        path='tmp-file-audit',
    )


Calculate Hash
--------------

.. automethod:: hvac.api.system_backend.Audit.calculate_hash
   :noindex:

Examples
````````

.. testsetup:: sys_audit_calculate_hash

    options = {
        'path': '/tmp/vault.audit.log'
    }

    client.sys.enable_audit_device(
        device_type='file',
        options=options,
        path='tmp-file-audit',
    )

.. testcode:: sys_audit_calculate_hash

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    input_to_hash = 'some sort of string thinger'

    audit_hash = client.sys.calculate_hash(
        path='tmp-file-audit',
        input_to_hash=input_to_hash,
    )

    print('The hash for the provided input is: %s' % audit_hash['data']['hash'])

Example output:

.. testoutput:: sys_audit_calculate_hash

    The hash for the provided input is: hmac-sha256:...

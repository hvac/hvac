Health
======

.. contents::
   :local:
   :depth: 1


Read Status
-----------

.. automethod:: hvac.api.system_backend.Health.read_health_status
   :noindex:

Examples
````````

.. testcode:: sys_health

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    status = client.sys.read_health_status(method='GET')
    print('Vault initialization status is: %s' % status['initialized'])

Example output:

.. testoutput:: sys_health

    Vault initialization status is: True

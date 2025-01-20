Leader
======

.. contents::
   :local:
   :depth: 1


Read Leader Status
------------------

.. automethod:: hvac.api.system_backend.Leader.read_leader_status
   :noindex:

Examples
````````

.. testcode:: sys_leader

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    status = client.sys.read_leader_status()
    print('HA status is: %s' % status['ha_enabled'])

Example output:

.. testoutput:: sys_leader

    HA status is: False

Step Down
---------

.. automethod:: hvac.api.system_backend.Leader.step_down
   :noindex:

Examples
````````

.. code:: python

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')
    client.sys.step_down()

Get Leader
------------------

.. automethod:: hvac.api.system_backend.Leader.get_leader
   :noindex:

Examples
````````

.. testcode:: sys_get_leader

    import hvac
    client = hvac.Client(cluster_url=['https://127.0.0.1:8200', 'https://127.0.0.1:8202','https://127.0.0.1:8204'])

    leader = client.sys.get_leader()
    print('Leader: %s' % leader)

Example output:

.. testoutput:: sys_get_leader

    Leader is: https://127.0.0.1:8200
Control Group
=============

.. contents::
   :local:
   :depth: 1

Authorize Control Group Request
--------------------------------

.. automethod:: hvac.api.system_backend.ControlGroup.authorize_control_group
   :noindex:

Examples
````````

.. code:: python

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.authorize_control_group(accessor='<wrapping-token-accessor>')

Check Control Group Request Status
-----------------------------------

.. automethod:: hvac.api.system_backend.ControlGroup.check_control_group_request
   :noindex:

Examples
````````

.. code:: python

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.check_control_group_request(accessor='<wrapping-token-accessor>')

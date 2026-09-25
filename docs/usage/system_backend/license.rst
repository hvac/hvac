License
=======

.. contents::
   :local:
   :depth: 1

Read License Status
-------------------

.. automethod:: hvac.api.system_backend.License.read_license_status
   :noindex:

Examples
````````

.. code:: python

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.read_license_status()

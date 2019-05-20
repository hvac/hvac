Seal
====

.. contents::
   :local:
   :depth: 1


Seal Status
-----------

.. autoattribute:: hvac.v1.Client.seal_status
   :noindex:

Examples
````````

.. testcode:: sys_seal

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    print('Is Vault sealed: %s' % client.seal_status['sealed'])

Example output:

.. testoutput:: sys_seal

    Is Vault sealed: False


Is Sealed
---------

.. automethod:: hvac.api.system_backend.Seal.is_sealed
   :noindex:

Examples
````````

.. testcode:: sys_seal

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    print('Is Vault sealed: %s' % client.sys.is_sealed())

Example output:

.. testoutput:: sys_seal

    Is Vault sealed: False


Read Seal Status
----------------

.. automethod:: hvac.api.system_backend.Seal.read_seal_status
   :noindex:

Examples
````````

.. testcode:: sys_seal

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    print('Is Vault sealed: %s' % client.sys.read_seal_status()['sealed'])

Example output:

.. testoutput:: sys_seal

    Is Vault sealed: False


Seal
----

.. automethod:: hvac.api.system_backend.Seal.seal
   :noindex:

Examples
````````

.. testsetup:: sys_seal_seal

    key = manager.keys[0]
    keys = manager.keys[1:]

.. testcode:: sys_seal_seal

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.seal()


Submit Unseal Key
-----------------

.. automethod:: hvac.api.system_backend.Seal.submit_unseal_key
   :noindex:

Examples
````````

.. testcode:: sys_seal_seal

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.submit_unseal_key(key=key)


Submit Unseal Keys
------------------

.. automethod:: hvac.api.system_backend.Seal.submit_unseal_keys
   :noindex:

Examples
````````

.. testcode:: sys_seal_seal

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.submit_unseal_keys(keys=keys)




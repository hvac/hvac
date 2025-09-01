Quota
=====

.. contents::
   :local:
   :depth: 1

.. testsetup:: sys_quota

    client.sys.enable_secrets_engine(
        backend_type='kv',
        path='kv',
    )

Read Quota
---------------

.. automethod:: hvac.api.system_backend.Quota.read_quota
   :noindex:

Examples
````````

.. testcode:: sys_quota
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    client.sys.create_or_update_quota(name="quota1", rate=100.0)

Create or Update Quota
----------------------

.. automethod:: hvac.api.system_backend.Quota.create_or_update_quota
   :noindex:

.. testcode:: sys_quota
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    # Create rate quota
    client.sys.create_or_update_quota(name="quota1", rate=100.0)

    # Update quota that already exists
    client.sys.create_or_update_quota(name="quota1", rate=101.0)

    # Create lease count quota, inheritable over the namespace
    client.sys.create_or_update_lease_quota(name="quota2", max_leases=1000, path="mynamespace/", inheritable=True)

List Quotas
---------------

.. automethod:: hvac.api.system_backend.Quota.list_quotas
   :noindex:

Examples
````````

.. testcode:: sys_quota
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    
    client.sys.create_or_update_quota(name="quota1", rate=1000.0, interval="10m")
    client.sys.create_or_update_quota(name="quota2", rate=1000.0, path="/kv")

Delete Quota
---------------

.. automethod:: hvac.api.system_backend.Quota.delete_quota
   :noindex:

Examples
````````

.. testcode:: sys_quota
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    
    client.sys.delete_quota(name="quota1")
    client.sys.delete_lease_quota(name="quota2")

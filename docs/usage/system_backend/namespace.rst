Namespace
=====

.. contents::
   :local:
   :depth: 1


Create Namespace
----------------

.. automethod:: hvac.api.system_backend.namespace.create_namespace
   :noindex:

Examples
````````

.. testcode:: sys_namespace
   
    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    # Create namespace team1 where team1 is a child of root
    client.sys.create_namespace(path="team1")

    # Create namespace team1/app1 where app1 is a child of team1
    client2 = hvac.Client(url='https://127.0.0.1:8200', namespace="team1")
    client2.sys.create_namespace(path="app1")

Example output:

    print(client.sys.create_namespace(path="team1"))
    {"request_id":"<redacted>","lease_id":"","renewable":false,"lease_duration":0,"data":{"id":"nf28f","path":"team1/"},"wrap_info":null,"warnings":null,"auth":null}

    print(client2.sys.create_namespace(path="app1"))
    {"request_id":"<redacted>","lease_id":"","renewable":false,"lease_duration":0,"data":{"id":"EGqRJ","path":"team1/app1/"},"wrap_info":null,"warnings":null,"auth":null}

List Mounted Secrets Engines
----------------------------

.. automethod:: hvac.api.system_backend.Namespace.list_namespaces
   :noindex:

Examples
````````

.. testcode:: sys_namespace
    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    client.sys.create_namespace(path='team1')

    client.sys.list_namespaces()

Example output:

    print(client.sys.list_namespaces())
    {"request_id":"<redacted>","lease_id":"","renewable":false,"lease_duration":0,"data":{"key_info":{"testns/":{"id":"ekiUn","path":"testns/"}},"keys":["testns/"]},"wrap_info":null,"warnings":null,"auth":null}


Delete Namespace
---------------------

.. automethod:: hvac.api.system_backend.Namespace.delete_namespace
   :noindex:

Examples
````````

.. testcode:: sys_namespace
    
    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    client.sys.create_namespace(path="team1")
    client2 = hvac.Client(url='https://127.0.0.1:8200', namespace="team1")
    client2.sys.create_namespace(path="app1")

    # Delete namespace app1 where app1 is a child of team1
    client2.sys.delete_namespace(path="app1")

    # Delete namespace team1
    client.sys.delete_namespace(path="team1")

Policy
======

.. contents::
   :local:
   :depth: 1

Manipulate policies
-------------------

.. testcode:: sys_policy

    policies = client.sys.list_policies()['data']['policies'] # => ['root']

    policy = """
    path "sys" {
      capabilities = ["deny"]
    }

    path "secret/*" {
      capabilities = ["read", "list"]
    }

    path "secret/foo" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }
    """

    client.sys.create_or_update_policy(
        name='secret-writer',
        policy=policy,
    )

    client.sys.delete_policy('oldthing')

    # The get_policy method offers some additional features and is available in the Client class.
    policy = client.get_policy('mypolicy')

    # Requires pyhcl to automatically parse HCL into a Python dictionary
    policy = client.get_policy('mypolicy', parse=True)

Using Python Variable(s) In Policy Rules
````````````````````````````````````````

.. testcode:: sys_policy

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')

    key = 'some-key-string'

    policy_body = """
    path "transit/encrypt/%s" {
        capabilities = ["update"]
    }
    """ % key
    client.sys.create_or_update_policy(
        name='my-policy-name',
        policy=policy_body,
    )


List Policies
-------------

.. automethod:: hvac.api.system_backend.Policy.list_policies
   :noindex:

Examples
````````

.. testcode:: sys_policy

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    list_policies_resp = client.sys.list_policies()['data']['policies']
    print('List of currently configured policies: %s' % ', '.join(list_policies_resp))

Example output:

.. testoutput:: sys_policy

    List of currently configured policies: default, my-policy-name, secret-writer, root


Read Policy
-----------

.. automethod:: hvac.api.system_backend.Policy.read_policy
   :noindex:

Examples
````````

.. testcode:: sys_policy

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    hvac_policy_rules = client.sys.read_policy(name='secret-writer')['data']['rules']
    print('secret-writer policy rules:\n%s' % hvac_policy_rules)

Example output:

.. testoutput:: sys_policy

    secret-writer policy rules:

    path "sys" {
      capabilities = ["deny"]
    }

    path "secret/*" {
      capabilities = ["read", "list"]
    }

    path "secret/foo" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }
    ...

Create Or Update Policy
-----------------------

.. automethod:: hvac.api.system_backend.Policy.create_or_update_policy
   :noindex:

Examples
````````

.. testcode:: sys_policy

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    policy = '''
        path "sys" {
            capabilities = ["deny"]
        }
        path "secret" {
            capabilities = ["create", "read", "update", "delete", "list"]
        }
    '''
    client.sys.create_or_update_policy(
        name='secret-writer',
        policy=policy,
    )

Delete Policy
-------------

.. automethod:: hvac.api.system_backend.Policy.delete_policy
   :noindex:

Examples
````````

.. testcode:: sys_policy

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.delete_policy(
        name='secret-writer',
    )

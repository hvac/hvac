Auth
====

.. contents::
   :local:
   :depth: 1


Examples
--------

.. testcode:: sys_auth

    methods = client.sys.list_auth_methods()

    client.sys.enable_auth_method('userpass', path='customuserpass')
    client.sys.disable_auth_method('github')

List Auth Methods
-----------------

.. automethod:: hvac.api.system_backend.Auth.list_auth_methods
   :noindex:

Examples
````````

.. testcode:: sys_auth_list

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    auth_methods = client.sys.list_auth_methods()
    print('The following auth methods are enabled: {auth_methods_list}'.format(
        auth_methods_list=', '.join(auth_methods['data'].keys()),
    ))

Example output:

.. testoutput:: sys_auth_list

    The following auth methods are enabled: token/


Enable Auth Method
------------------

.. automethod:: hvac.api.system_backend.Auth.enable_auth_method
   :noindex:

Examples
````````

.. testcode:: sys_auth

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.enable_auth_method(
        method_type='github',
        path='github-hvac',
    )


Disable Auth Method
-------------------

.. automethod:: hvac.api.system_backend.Auth.disable_auth_method
   :noindex:

Examples
````````

.. testcode:: sys_auth

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.disable_auth_method(
        path='github-hvac',
    )


Read Auth Method Tuning
-----------------------

.. automethod:: hvac.api.system_backend.Auth.read_auth_method_tuning
   :noindex:

Examples
````````

.. testsetup:: sys_auth_read

    client.sys.enable_auth_method(
        method_type='github',
        path='github-hvac',
    )

.. testcode:: sys_auth_read

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')
    response = client.sys.read_auth_method_tuning(
        path='github-hvac',
    )

    print('The max lease TTL for the auth method under path "github-hvac" is: {max_ttl}'.format(
        max_ttl=response['data']['max_lease_ttl'],
    ))

Example output:

.. testoutput:: sys_auth_read

    The max lease TTL for the auth method under path "github-hvac" is: 2764800


Tune Auth Method
----------------

.. automethod:: hvac.api.system_backend.Auth.tune_auth_method
   :noindex:

Examples
````````

.. testsetup:: sys_auth_tune

    client.sys.enable_auth_method(
        method_type='github',
        path='github-hvac',
    )

.. testcode:: sys_auth_tune

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.tune_auth_method(
        path='github-hvac',
        description='The Github auth method for hvac users',
    )




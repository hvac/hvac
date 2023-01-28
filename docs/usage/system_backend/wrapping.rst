Wrapping
========

.. contents::
   :local:
   :depth: 1


Unwrap
------

.. automethod:: hvac.api.system_backend.Wrapping.unwrap
   :noindex:

Examples
````````

.. testsetup:: sys_wrapping

    client.sys.enable_auth_method(
        method_type='approle',
        path='approle-test',
    )

.. testcode:: sys_wrapping

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')
    client.write(
        path="auth/approle-test/role/testrole",
    )
    result = client.write(
        path='auth/approle-test/role/testrole/secret-id',
        wrap_ttl="10s",
    )

    unwrap_response = client.sys.unwrap(
        token=result['wrap_info']['token'],
    )
    print('Unwrapped approle role token secret id accessor: "%s"' % unwrap_response['data']['secret_id_accessor'])

Example output:

.. testoutput:: sys_wrapping

    Unwrapped approle role token secret id accessor: "..."


.. testcode:: sys_wrapping

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')
    client.write(
        path="auth/approle-test/role/testrole",
    )
    result = client.write(
        path='auth/approle-test/role/testrole/secret-id',
        wrap_ttl="10s",
    )
    result_token = result['wrap_info']['token']

    unwrapping_client = hvac.Client(url='https://127.0.0.1:8200', token=result_token)

    # Do not pass the token to unwrap when authenticating with the wrapping token
    unwrap_response = unwrapping_client.sys.unwrap()

    print('Unwrapped approle role token secret id accessor: "%s"' % unwrap_response['data']['secret_id_accessor'])

Example output:

.. testoutput:: sys_wrapping

    Unwrapped approle role token secret id accessor: "..."


.. testcleanup:: sys_wrapping

    client.sys.disable_auth_method(
        path='approle-test',
    )

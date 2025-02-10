Tools
=======

.. contents::
   :local:
   :depth: 1


Generate Random Bytes
---------------------

.. automethod:: hvac.api.system_backend.Tools.generate_random_bytes
   :noindex:

Examples
````````

.. testcode:: sys_tools

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    gen_bytes_response = client.sys.generate_random_bytes(n_bytes=32)
    random_bytes = gen_bytes_response['data']['random_bytes']
    print('Here are some random bytes: {bytes}'.format(bytes=random_bytes))

Example output:

.. testoutput:: sys_tools

    Here are some random bytes: ...

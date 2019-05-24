Init
====

.. contents::
   :local:
   :depth: 1


Read Status
-----------

.. automethod:: hvac.api.system_backend.Init.read_init_status
   :noindex:

Examples
````````

.. testcode:: sys_init

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')

    read_response = client.sys.read_init_status()
    print('Vault initialize status: %s' % read_response['initialized'])

Example output:

.. testoutput:: sys_init

    Vault initialize status: True


Is Initialized
--------------

.. automethod:: hvac.api.system_backend.Init.is_initialized
   :noindex:

Examples
````````

.. testcode:: sys_init

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')

    print('Vault initialize status: %s' % client.sys.is_initialized())

Example output:

.. testoutput:: sys_init

    Vault initialize status: True


Initialize
----------

.. automethod:: hvac.api.system_backend.Init.initialize
   :noindex:

Examples
````````

.. testsetup:: sys_init_mock

    from requests_mock.mocker import Mocker

    init_mocker = Mocker(real_http=True)
    init_mocker.start()
    mock_response = {
        'root_token': '',
        'keys': [],
    }
    mock_url = 'https://127.0.0.1:8200/v1/sys/init'
    init_mocker.register_uri(
        method='PUT',
        url=mock_url,
        json=mock_response
    )

.. testcode:: sys_init_mock

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')

    init_result = client.sys.initialize()

    root_token = init_result['root_token']
    unseal_keys = init_result['keys']

.. testcleanup:: sys_init_mock

    init_mocker.stop()

When called for a previously initialized Vault cluster, an exception is raised:

.. testcode:: sys_init

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')

    init_result = client.sys.initialize()

Example output:

.. testoutput:: sys_init

    Traceback (most recent call last):
      ...
    hvac.exceptions.InvalidRequest: Vault is already initialized


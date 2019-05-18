Lease
=====

.. contents::
   :local:
   :depth: 1

.. testsetup:: sys_lease, sys_lease_revoke

    test_utils.configure_pki(client)
    pki_issue_response = client.write(
        path='pki/issue/my-role',
        common_name='test.hvac.com',
    )
    lease_id = pki_issue_response['lease_id']

View and Manage Leases
----------------------

Read a lease:

.. doctest:: sys_lease

    >>> read_lease_response = client.sys.read_lease(lease_id=lease_id)
    >>> print('Expire time for lease ID {id} is: {expire_time}'.format(
    ...     id=lease_id,
    ...     expire_time=read_lease_response['data']['expire_time'],
    ... ))
    Expire time for lease ID pki/issue/my-role/... is: 20...

Renewing a lease:

.. testsetup:: sys_lease_renew

    from requests_mock.mocker import Mocker

    lease_id = 'pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f'
    mocker = Mocker(real_http=False)
    mocker.start()
    mock_response = {'lease_id': lease_id, 'lease_duration': 2764790, 'renewable': True}
    mock_urls = [
        'https://127.0.0.1:8200/v1/sys/leases/renew',
        'https://localhost:8200/v1/sys/leases/renew',
    ]
    for mock_url in mock_urls:
        mocker.register_uri(
            method='PUT',
            url=mock_url,
            json=mock_response
        )

.. doctest:: sys_lease_renew

    >>> renew_lease_resp = client.sys.renew_lease(lease_id=lease_id)
    >>> print('Lease ID: "{id}" renewed, lease duration: "{duration}"'.format(
    ...     id=renew_lease_resp['lease_id'],
    ...     duration=renew_lease_resp['lease_duration'],
    ... ))
    Lease ID: "pki/issue/my-role/d05138a2-edeb-889d-db98-2057ecd5138f" renewed, lease duration: "2764790"

.. testcleanup:: sys_lease_renew

    mocker.stop()

Revoking a lease:

.. doctest:: sys_lease_revoke

    >>> client.sys.revoke_lease(lease_id=lease_id)
    <Response [204]>

Read Lease
----------

.. automethod:: hvac.api.system_backend.Lease.read_lease
   :noindex:

Examples
````````

.. testcode:: sys_lease

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    read_lease_resp = client.sys.read_lease(
        lease_id=lease_id,
    )

    # expire_time in the form of something like: 2019-02-25T07:41:30.000038-06:00
    print('Current expire time for lease ID {id} is: {expires}'.format(
        id=lease_id,
        expires=read_lease_resp['data']['expire_time'],
    ))

Example output:

.. testoutput:: sys_lease

    Current expire time for lease ID pki/issue/my-role/... is: ...


List Leases
-----------

.. automethod:: hvac.api.system_backend.Lease.list_leases
   :noindex:

Examples
````````

.. testcode:: sys_lease

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    list_leases_response = client.sys.list_leases(
        prefix='pki',
    )
    print('The follow lease keys are active under the "pki" prefix: %s' % list_leases_response['data']['keys'])


Example output:

.. testoutput:: sys_lease

    The follow lease keys are active under the "pki" prefix: ['issue/']

Renew Lease
-----------

.. automethod:: hvac.api.system_backend.Lease.renew_lease
   :noindex:

Examples
````````

.. testcode:: sys_lease_renew

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.renew_lease(
        lease_id=lease_id,
        increment=500,
    )


Revoke Lease
------------

.. automethod:: hvac.api.system_backend.Lease.revoke_lease
   :noindex:

Examples
````````

.. testcode:: sys_lease

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.revoke_lease(
        lease_id=lease_id,
    )


Revoke Prefix
-------------

.. automethod:: hvac.api.system_backend.Lease.revoke_prefix
   :noindex:

Examples
````````

.. testcode:: sys_lease

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.revoke_prefix(
        prefix='pki',
    )


Revoke Force
------------

.. automethod:: hvac.api.system_backend.Lease.revoke_force
   :noindex:

Examples
````````

.. testcode:: sys_lease

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.revoke_force(
        prefix='pki',
    )

.. testcleanup:: sys_lease

    test_utils.disable_pki(client)




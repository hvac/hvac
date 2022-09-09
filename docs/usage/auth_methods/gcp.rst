.. _gcp-auth-method:

GCP
===

.. note::
    Every method under the :py:attr:`Client class's gcp.auth attribute<hvac.api.Gcp.auth>` includes a `mount_point` parameter that can be used to address the GCP auth method under a custom mount path. E.g., If enabling the GCP auth method using Vault's CLI commands via `vault auth enable -path=my-gcp gcp`", the `mount_point` parameter in :py:meth:`hvac.api.auth.Gcp` methods would be set to "my-gcp".

Enabling the Auth Method
------------------------

Source reference: :py:meth:`hvac.api.SystemBackend.enable_auth_method`

.. code:: python

    import hvac
    client = hvac.Client()

    gcp_auth_path = 'company-gcp'
    description = 'Auth method for use by team members in our company's Gcp organization'

    if '%s/' % gcp_auth_path not in vault_client.sys.list_auth_methods()['data']:
        print('Enabling the gcp auth backend at mount_point: {path}'.format(
            path=gcp_auth_path,
        ))
        client.sys.enable_auth_method(
            method_type='gcp',
            description=description,
            path=gcp_auth_path,
        )


Configure
---------

Source reference: :py:meth:`hvac.api.auth.Gcp.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.gcp.configure(
        credentials='some signed JSON web token for the Vault server...'
    )

Read Config
-----------

Source reference: :py:meth:`hvac.api.auth.Gcp.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    read_config = client.auth.gcp.read_config()
    print('The configured project_id is: {id}'.format(id=read_config['project_id'))

Delete Config
-------------

Source reference: :py:meth:`hvac.api.auth.Gcp.delete_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.gcp.delete_config()

Create Role
-----------

Source reference: :py:meth:`hvac.api.auth.Gcp.create_role`

.. code:: python

    import hvac
    client = hvac.Client()

	client.auth.gcp.create_role(
		name='some-gcp-role-name',
		role_type='iam',
		project_id='some-gcp-project-id',
		bound_service_accounts=['*'],
	)

Edit Service Accounts On IAM Role
---------------------------------

Source reference: :py:meth:`hvac.api.auth.Gcp.edit_service_accounts_on_iam_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.edit_service_accounts_on_iam_role(
		name='some-gcp-role-name',
        add=['hvac@appspot.gserviceaccount.com'],
    )

    client.gcp.edit_service_accounts_on_iam_role(
		name='some-gcp-role-name',
        remove=['disallowed-service-account@appspot.gserviceaccount.com'],
    )

Edit Labels On GCE Role
-----------------------

Source reference: :py:meth:`hvac.api.auth.Gcp.edit_labels_on_gce_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.edit_labels_on_gce_role(
		name='some-gcp-role-name',
        add=['some-key:some-value'],
    )

    client.gcp.edit_labels_on_gce_role(
		name='some-gcp-role-name',
        remove=['some-bad-key:some-bad-value'],
    )

Read A Role
-----------

Source reference: :py:meth:`hvac.api.auth.Gcp.read_role`

.. code:: python

    import hvac
    client = hvac.Client()

    read_role_response = client.gcp.read_role(
        name=role_name,
    )

    print('Policies for role "{name}": {policies}'.format(
        name='my-role',
        policies=','.join(read_role_response['policies']),
    ))

List Roles
----------

Source reference: :py:meth:`hvac.api.auth.Gcp.list_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    roles = client.auth.gcp.list_roles()
    print('The following GCP auth roles are configured: {roles}'.format(
        roles=','.join(roles['keys']),
    ))

Delete A Role
-------------

Source reference: :py:meth:`hvac.api.auth.Gcp.delete_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.delete_role(
    )

Login
-----

Source reference: :py:meth:`hvac.api.auth.Gcp.login`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.login(
        role=role_name,
        jwt='some signed JSON web token...',
    )
    client.is_authenticated  # ==> returns True


Example with google-api-python-client Usage
```````````````````````````````````````````

.. code:: python

    import time

    import googleapiclient.discovery # pip install google-api-python-client
    from google.oauth2 import service_account # pip install google-auth
    import hvac # pip install hvac

    # First load some previously generated GCP service account key
    path_to_sa_json = 'some-service-account-path.json'
    credentials = service_account.Credentials.from_service_account_file(path_to_sa_json)
    with open(path_to_sa_json, 'r') as f:
        creds = json.load(f)
        project = creds['project_id']
        service_account = creds['client_email']

    # Generate a payload for subsequent "signJwt()" call
    # Reference: https://google-auth.readthedocs.io/en/latest/reference/google.auth.jwt.html#google.auth.jwt.Credentials
    now = int(time.time())
    expires = now + 900  # 15 mins in seconds, can't be longer.
    payload = {
        'iat': now,
        'exp': expires,
        'sub': service_account,
        'aud': 'vault/my-role'
    }
    body = {'payload': json.dumps(payload)}
    name = f'projects/{project}/serviceAccounts/{service_account}'

    # Perform the GCP API call
    iam = googleapiclient.discovery.build('iam', 'v1', credentials=credentials)
    request = iam.projects().serviceAccounts().signJwt(name=name, body=body)
    resp = request.execute()
    jwt = resp['signedJwt']

    # Perform hvac call to configured GCP auth method
    client.auth.gcp.login(
        role='my-role',
        jwt=jwt,
    )

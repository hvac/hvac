AWS
===

.. contents::

Configure Root IAM Credentials
------------------------------

Source reference: :py:meth:`hvac.api.secrets_engines.Aws.configure_root_iam_credentials`

.. code:: python

    import os

    import hvac
    client = hvac.Client()

    client.secrets.aws.configure_root_iam_credentials(
        access_key=os.getenv('AWS_ACCESS_KEY_ID'),
        secret_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    )

Rotate Root IAM Credentials
---------------------------

Source reference: :py:meth:`hvac.api.secrets_engines.Aws.rotate_root_iam_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.aws.rotate_root_iam_credentials()

Configure Lease
---------------

Source reference: :py:meth:`hvac.api.secrets_engines.Aws.configure_lease`

.. code:: python

    import hvac
    client = hvac.Client()

    # Set the default least TTL to 300 seconds / 5 minutes
    client.secrets.aws.configure_lease(
        lease='300s',
    )

Read Lease
----------

Source reference: :py:meth:`hvac.api.secrets_engines.Aws.read_lease`

.. code:: python

    import hvac
    client = hvac.Client()

    read_lease_response = client.secrets.aws.read_lease()
    print('The current "lease_max" TTL is: {lease_max}'.format(
        lease_max=read_lease_response['data']['lease_max'],
    ))

Create or Update Role
---------------------

Source reference: :py:meth:`hvac.api.secrets_engines.Aws.create_or_update_role`

.. code:: python

    import hvac
    client = hvac.Client()

    describe_ec2_policy_doc = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Resource': '*'
                'Action': 'ec2:Describe*',
                'Effect': 'Allow',
            },
        ],
    }
    client.secrets.aws.create_or_update_role(
        name='hvac-role',
        credential_type='assumed_role',
        policy_document=describe_ec2_policy_doc,
        policy_arns=['arn:aws:iam::aws:policy/AmazonVPCReadOnlyAccess'],
    )

Legacy Parameters
`````````````````

.. note::
    In previous versions of Vault (before version 0.11.0), this API route only supports the `policy_document` and `policy_arns` parameters (which hvac will translate to `policy` and `arn` parameters respectively in the request sent to Vault). If running these versions of Vault, the `legacy_params` parameter on this method can be set to `True`.

For older versions of Vault (any version before 0.11.0):

.. code:: python

    import hvac
    client = hvac.Client()

    describe_ec2_policy_doc = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Resource': '*'
                'Action': 'ec2:Describe*',
                'Effect': 'Allow',
            },
        ],
    }

    # Note: with the legacy params, the `policy_arns` parameter is translated to `arn`
    # in the request sent to Vault and only one ARN is accepted. If a list is provided,
    # hvac will only use the first ARN in the list.
    client.secrets.aws.create_or_update_role(
        name='hvac-role',
        credential_type='assumed_role',
        policy_document=describe_ec2_policy_doc,
        policy_arns='arn:aws:iam::aws:policy/AmazonVPCReadOnlyAccess',
        legacy_params=True,
    )

Read Role
---------

Source reference: :py:meth:`hvac.api.secrets_engines.Aws.read_role`

.. code:: python

    import hvac
    client = hvac.Client()

    read_role_response = client.secrets.aws.read_role(
        name='hvac-role',
    )
    print('The credential type for role "hvac-role" is: {cred_type}'.format(
        cred_type=read_role_response['data']['credential_types'],
    ))


List Roles
----------

Source reference: :py:meth:`hvac.api.secrets_engines.Aws.list_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    list_roles_response = client.secrets.aws.list_roles()
    print('AWS secrets engine role listing: {roles}'.format(
        roles=', '.join(list_roles_response['data']['keys'])
    ))

Delete Role
-----------

Source reference: :py:meth:`hvac.api.secrets_engines.Aws.delete_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.aws.delete_role(
        name='hvac-role',
    )

Generate Credentials
--------------------

Source reference: :py:meth:`hvac.api.secrets_engines.Aws.generate_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    gen_creds_response = client.secrets.aws.generate_credentials(
        name='hvac-role',
    )
    print('Generated access / secret keys: {access} / {secret}'.format(
        access=gen_creds_response['data']['access_key'],
        secret=gen_creds_response['data']['secret_key'],
    ))

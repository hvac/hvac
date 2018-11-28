Aws Auth Method
==================

.. note::
    Every method under the :py:attr:`Client class's aws attribute<hvac.v1.Client.aws>` includes a `mount_point` parameter that can be used to address the Aws secret engine under a custom mount path. E.g., If enabling the Aws secret engine using Vault's CLI commands via `vault secret enable -path=my-aws aws`", the `mount_point` parameter in :py:meth:`hvac.api.secrets_engines.Aws` methods would be set to "my-aws".

Enabling the Auth Method
------------------------

:py:meth:`hvac.v1.Client.enable_secret_backend`

.. code:: python

    import hvac
    client = hvac.Client()

    aws_secret_path = 'company-aws'
    description = 'Auth method for use by team members in our company's Aws organization'

    if '%s/' % aws_secret_path not in vault_client.list_secret_backends():
        print('Enabling the aws secret backend at mount_point: {path}'.format(
            path=aws_secret_path,
        ))
        client.enable_secret_backend(
            backend_type='aws',
            description=description,
            mount_point=aws_secret_path,
        )


configure-root-iam-credentials
-------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.configure_root_iam_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.configure_root_iam_credentials(
    )

rotate-root-iam-credentials
-------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.rotate_root_iam_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.rotate_root_iam_credentials(
    )

configure-lease
-------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.configure_lease`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.configure_lease(
    )

read-lease
-------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.read_lease`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.read_lease(
    )

create-update-role
-------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.create_or_update_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.create_or_update_role(
    )

read-role
-------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.read_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.read_role(
    )

list-roles
-------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.list_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.list_roles(
    )

delete-role
-------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.delete_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.delete_role(
    )

generate-credentials
-------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.generate_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.generate_credentials(
    )

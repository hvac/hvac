GCP
===
=======
Gcp Auth Method
==================

.. note::
    Every method under the :py:attr:`Client class's gcp attribute<hvac.v1.Client.gcp>` includes a `mount_point` parameter that can be used to address the Gcp auth method under a custom mount path. E.g., If enabling the Gcp auth method using Vault's CLI commands via `vault auth enable -path=my-gcp gcp`", the `mount_point` parameter in :py:meth:`hvac.api.auth.Gcp` methods would be set to "my-gcp".

Enabling the Auth Method
------------------------

:py:meth:`hvac.v1.Client.enable_auth_backend`

.. code:: python

    import hvac
    client = hvac.Client()

    gcp_auth_path = 'company-gcp'
    description = 'Auth method for use by team members in our company's Gcp organization'

    if '%s/' % gcp_auth_path not in vault_client.list_auth_backends():
        print('Enabling the gcp auth backend at mount_point: {path}'.format(
            path=gcp_auth_path,
        ))
        client.enable_auth_backend(
            backend_type='gcp',
            description=description,
            mount_point=gcp_auth_path,
        )


configure
-------------------------------

:py:meth:`hvac.api.auth.Gcp.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.configure(
    )

read-config
-------------------------------

:py:meth:`hvac.api.auth.Gcp.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.read_config(
    )

delete-config
-------------------------------

:py:meth:`hvac.api.auth.Gcp.delete_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.delete_config(
    )

create-role
-------------------------------

:py:meth:`hvac.api.auth.Gcp.create_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.create_role(
    )

edit-service-accounts-on-iam-role
-------------------------------

:py:meth:`hvac.api.auth.Gcp.edit_service_accounts_on_iam_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.edit_service_accounts_on_iam_role(
    )

edit-labels-on-gce-role
-------------------------------

:py:meth:`hvac.api.auth.Gcp.edit_labels_on_gce_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.edit_labels_on_gce_role(
    )

read-role
-------------------------------

:py:meth:`hvac.api.auth.Gcp.read_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.read_role(
    )

list-roles
-------------------------------

:py:meth:`hvac.api.auth.Gcp.list_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.list_roles(
    )

delete-role
-------------------------------

:py:meth:`hvac.api.auth.Gcp.delete_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.delete_role(
    )

login
-------------------------------

:py:meth:`hvac.api.auth.Gcp.login`

.. code:: python

    import hvac
    client = hvac.Client()

    client.gcp.login(
    )

Aws
===

Configure Root IAM Credentials
------------------------------

:py:meth:`hvac.api.secrets_engines.Aws.configure_root_iam_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.configure_root_iam_credentials(
    )

Rotate Root IAM Credentials
---------------------------

:py:meth:`hvac.api.secrets_engines.Aws.rotate_root_iam_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.rotate_root_iam_credentials(
    )

Configure Lease
---------------

:py:meth:`hvac.api.secrets_engines.Aws.configure_lease`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.configure_lease(
    )

Read Lease
----------

:py:meth:`hvac.api.secrets_engines.Aws.read_lease`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.read_lease(
    )

Create or Update Role
---------------------

:py:meth:`hvac.api.secrets_engines.Aws.create_or_update_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.create_or_update_role(
    )

Read Role
---------

:py:meth:`hvac.api.secrets_engines.Aws.read_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.read_role(
    )

List Roles
----------

:py:meth:`hvac.api.secrets_engines.Aws.list_roles`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.list_roles(
    )

Delete Role
-----------

:py:meth:`hvac.api.secrets_engines.Aws.delete_role`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.delete_role(
    )

Generate Credentials
--------------------

:py:meth:`hvac.api.secrets_engines.Aws.generate_credentials`

.. code:: python

    import hvac
    client = hvac.Client()

    client.aws.generate_credentials(
    )

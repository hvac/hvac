.. _azure-auth-method:

Azure Auth Method
==================

.. note::
    Every method under the :py:attr:`Client class's azure attribute<hvac.v1.Client.azure.auth>` includes a `mount_point` parameter that can be used to address the Azure auth method under a custom mount path. E.g., If enabling the Azure auth method using Vault's CLI commands via `vault auth enable -path=my-azure azure`", the `mount_point` parameter in :py:meth:`hvac.api.auth.Azure` methods would be set to "my-azure".

Enabling the Auth Method
------------------------

:py:meth:`hvac.v1.Client.enable_auth_backend`

.. code:: python

    import hvac
    client = hvac.Client()

    azure_auth_path = 'company-azure'
    description = 'Auth method for use by team members in our company's Azure organization'

    if '%s/' % azure_auth_path not in vault_client.list_auth_backends():
        print('Enabling the azure auth backend at mount_point: {path}'.format(
            path=azure_auth_path,
        ))
        client.enable_auth_backend(
            backend_type='azure',
            description=description,
            mount_point=azure_auth_path,
        )

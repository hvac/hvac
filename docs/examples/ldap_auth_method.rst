LDAP Auth Backend
=================

Authentication
--------------

Generic authentication with an LDAP username and password:

.. code:: python

    client.auth_ldap('MY_USERNAME', 'MY_PASSWORD')
    client.auth_userpass('MY_USERNAME', 'MY_PASSWORD')

Using a custom mount_point:


.. code:: python

    # For a LDAP backend mounted under a non-default (ldap) path.
    # E.g., via Vault CLI with `vault auth enable -path=prod-ldap ldap`
    from getpass import getpass

    import hvac

    service_account_username = 'someuser'
    password_prompt = 'Please enter your password for the LDAP authentication backend: '
    service_account_password = getpass(prompt=password_prompt)

    client = hvac.Client()

    # Here the mount_point parameter corresponds to the path provided when enabling the backend
    client.auth_ldap(
        username=service_account_username,
        password=service_account_password,
        mount_point='prod-ldap'
    )
    print(client.is_authenticated)  # => True

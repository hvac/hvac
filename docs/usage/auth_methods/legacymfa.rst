Legacy MFA
==========

Configure Legacy MFA Auth Method Settings
-----------------------------------------

:py:meth:`hvac.api.auth_methods.LegacyMfa.configure`

.. note::
	The legacy/unsupported MFA auth method covered by this class's configuration API route only supports integration with a subset of Vault auth methods. See the list of supported auth methods in this module's :py:attr:`"SUPPORTED_AUTH_METHODS" attribute<hvac.api.auth_methods.LegacyMfa.SUPPORTED_AUTH_METHODS>` and/or the associated `Vault LegacyMFA documentation`_ for additional information.

.. _Vault LegacyMFA documentation: https://developer.hashicorp.com/vault/docs/v1.10.x/auth/mfa

.. code:: python

    import hvac
    client = hvac.Client()

    userpass_auth_path = 'some-userpass'

    if '%s/' % userpass_auth_path not in vault_client.sys.list_auth_methods()['data']:
        print('Enabling the userpass auth backend at mount_point: {path}'.format(
            path=userpass_auth_path,
        ))
        client.sys.enable_auth_method(
            method_type='userpass',
            path=userpass_auth_path,
        )

    client.auth.legacymfa.configure(
        mount_point=userpass_auth_path,
    )

Reading the Legacy MFA Auth Method Configuration
------------------------------------------------

:py:meth:`hvac.api.auth_methods.LegacyMfa.read_configuration`

.. code:: python

    import hvac
    client = hvac.Client()

    mfa_configuration = client.auth.legacymfa.read_configuration()
    print('The LegacyMFA auth method is configured with a MFA type of: {mfa_type}'.format(
        mfa_type=mfa_configuration['data']['type']
    )

Configure Duo LegacyMFA Type Access Credentials
-----------------------------------------------

:py:meth:`hvac.api.auth_methods.LegacyMfa.configure_duo_access`

.. code:: python

    from getpass import getpass

    import hvac
    client = hvac.Client()

    secret_key_prompt = 'Please enter the Duo access secret key to configure: '
    duo_access_secret_key = getpass(prompt=secret_key_prompt)

    client.auth.legacymfa.configure_duo_access(
        mount_point=userpass_auth_path,
        host='api-1234abcd.duosecurity.com',
        integration_key='SOME_DUO_IKEY',
        secret_key=duo_access_secret_key,
    )

Configure Duo Legacy MFA Type Behavior
--------------------------------------

:py:meth:`hvac.api.auth_methods.LegacyMfa.configure_duo_behavior`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.legacymfa.configure_duo_behavior(
        mount_point=userpass_auth_path,
        username_format='%s@hvac.network',
    )


Read Duo Legacy MFA Type Behavior
---------------------------------

:py:meth:`hvac.api.auth_methods.LegacyMfa.read_duo_behavior_configuration`

.. code:: python

    import hvac
    client = hvac.Client()

    duo_behavior_config = client.auth.legacymfa.read_duo_behavior_configuration(
        mount_point=userpass_auth_path,
    )
    print('The Duo LegacyMFA behavior is configured with a username_format of: {username_format}'.format(
        username_format=duo_behavior_config['data']['username_format'],
    )

Authentication / Login
----------------------

.. code:: python

    from getpass import getpass

    import hvac

    login_username = 'someuser'
    password_prompt = 'Please enter your password for the userpass (with MFA) authentication backend: '
    login_password = getpass(prompt=password_prompt)
    passcode_prompt = 'Please enter your OTP for the userpass (with MFA) authentication backend: '
    userpass_mfa_passcode = getpass(prompt=passcode_prompt)

    client = hvac.Client()

    # Here the mount_point parameter corresponds to the path provided when enabling the backend
    client.auth.legacymfa.auth_userpass(
        username=login_username,
        password=login_password,
        mount_point=userpass_auth_path,
        passcode=userpass_mfa_passcode,
    )
    print(client.is_authenticated)  # => True

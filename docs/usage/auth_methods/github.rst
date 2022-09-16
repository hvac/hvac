GitHub
======

.. note::
    Every method under the :py:attr:`Client class's github attribute<hvac.v1.Client.github>` includes a `mount_point` parameter that can be used to address the Github auth method under a custom mount path. E.g., If enabling the Github auth method using Vault's CLI commands via `vault auth enable -path=my-github github`", the `mount_point` parameter in :py:meth:`hvac.api.auth_methods.Github` methods would be set to "my-github".

Enabling the Auth Method
------------------------

:py:meth:`hvac.api.SystemBackend.enable_auth_method`

.. code:: python

    import hvac
    client = hvac.Client()

    github_auth_path = 'company-github'
    description = 'Auth method for use by team members in our company's Github organization'

    if '%s/' % github_auth_path not in vault_client.sys.list_auth_methods()['data']:
        print('Enabling the github auth backend at mount_point: {path}'.format(
            path=github_auth_path,
        ))
        client.sys.enable_auth_method(
            method_type='github',
            description=description,
            path=github_auth_path,
        )

Configure Connection Parameters
-------------------------------

:py:meth:`hvac.api.auth_methods.Github.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.github.configure(
        organization='our-lovely-company',
        max_ttl='48h',  # i.e., A given token can only be renewed for up to 48 hours
    )

Reading Configuration
---------------------

:py:meth:`hvac.api.auth_methods.Github.read_configuration`

.. code:: python

    import hvac
    client = hvac.Client()

    github_config = client.auth.github.read_configuration()
    print('The Github auth method is configured with a ttl of: {ttl}'.format(
        ttl=github_config['data']['ttl']
    )


Mapping Teams to Policies
-------------------------

:py:meth:`hvac.api.auth_methods.Github.map_team`

.. code:: python

    import hvac
    client = hvac.Client()

    teams = [
        dict(name='some-dev-team', policies=['dev-team']),
        dict(name='admin-team', policies=['administrator']),
    ]
    for team in teams:
        client.auth.github.map_team(
            team_name=team['name'],
            policies=team['policies'],
        )

Reading Team Mappings
---------------------

:py:meth:`hvac.api.auth_methods.Github.read_team_mapping`

.. code:: python

    import hvac
    client = hvac.Client()

    team_name = 'my-super-cool-team'
    github_config = client.auth.github.read_team_mapping(
        team_name=team_name,
    )
    print('The Github team {team} is mapped to the following policies: {policies}'.format(
        team=team_name,
        policies=github_config['data']['value'],
    )


Mapping Users to Policies
-------------------------

:py:meth:`hvac.api.auth_methods.Github.map_user`

.. code:: python

    import hvac
    client = hvac.Client()

    users = [
        dict(name='some-dev-user', policies=['dev-team']),
        dict(name='some-admin-user', policies=['administrator']),
    ]
    for user in users:
        client.auth.github.map_user(
            user_name=user['name'],
            policies=user['policies'],
        )

Reading User Mappings
---------------------

:py:meth:`hvac.api.auth_methods.Github.read_user_mapping`

.. code:: python

    import hvac
    client = hvac.Client()

    user_name = 'some-dev-user'
    github_config = client.auth.github.read_user_mapping(
        user_name=user_name,
    )
    print('The Github user "{user}" is mapped to the following policies: {policies}'.format(
        user=user_name,
        policies=github_config['data']['value'],
    )

Authentication / Login
----------------------

:py:meth:`hvac.api.auth_methods.Github.login`

Log in and automatically update the underlying "token" attribute on the :py:meth:`hvac.adapters.Adapter` instance:

.. code:: python

    import hvac
    client = hvac.Client()
    login_response = client.auth.github.login(token='some personal github token')

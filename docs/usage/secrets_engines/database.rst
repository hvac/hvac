DATABASE
===

.. contents::
   :local:
   :depth: 1

.. testsetup:: Database_secrets

    from requests_mock import ANY

    client.sys.enable_secrets_engine('Database')

    # mock out external calls that are diffcult to support in test environments
    mock_urls = {
        'https://127.0.0.1:8200/v1/Database/rolesets': 'LIST',
        'https://127.0.0.1:8200/v1/Database/roleset/hvac-doctest': ANY,
        'https://127.0.0.1:8200/v1/Database/roleset/hvac-doctest/rotate': 'POST',
        'https://127.0.0.1:8200/v1/Database/roleset/hvac-doctest/rotate-key': 'POST',
        'https://127.0.0.1:8200/v1/Database/token/hvac-doctest': 'GET',
        'https://127.0.0.1:8200/v1/Database/key/hvac-doctest': 'POST',
    }
    for mock_url, method in mock_urls.items():
        mocker.register_uri(
            method=method,
            url=mock_url,
            json=dict(),
        )

Configure
---------

.. automethod:: hvac.api.secrets_engines.Database.configure
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.enable_secrets_engine("database")

    # postgess example - you need to include creation params from vault docs as the
    # args, kwargs of this method.
    credentials = test_utils.load_config_file('example.jwt.json')
    configure_response = client.secrets.database.configure(
        name="testdb",
        plugin_name="postgresql-database-plugin",
        verify_connection=True,
        allowed_roles=["read"],
        root_rotation_statements=[],
        max_ttl=3600,
        connection_url="postgresql://{{username}}:{{password}}@postgres:5432/{{name}}?sslmode=disable",
        username="SecurityNightmare",
        password="Password"
    )
    print(configure_response)

    client.secrets.database.create_role("read",
        "testdb",
        "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
        default_ttl="1h",
        max_ttl="24h")

Example output:

.. testoutput:: database_secrets

    [needs result here]

Rotate Root Credentials
-----------------------

.. automethod:: hvac.api.sercets_engines.database.rotate_root_credentials
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    rotate_root_credentials_response = client.secrets.Database.rotate_root_credentials('testdb')
    print(rotate_root_credentials_response)

Example output:

.. testouput:: Database_secrets

    [output goes here]


Read Connection
---------------

.. automethod:: hvac.api.secrets_engines.Database.read_connection
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    read_connnection_response = client.secrets.Database.read_connnection("testdb")
    print('Max TTL for Database secrets engine set to: {max_ttl}'.format(max_ttl=read_connection_response['data']['max_ttl']))

Example output:

.. testoutput:: Database_secrets

    Max TTL for Database secrets engine set to: 3600


List Connections
----------------

.. automethod:: hvac.api.secrets_engines.Database.list_connections
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    list_connnections_response = client.secrets.Database.list_connnections()
    print(list_connections_response)

Example output:

.. testoutput:: Database_secrets

    [needs output]


Delete Connection
----------------

.. automethod:: hvac.api.secrets_engines.Database.delete_connection
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    delete_connnection_response = client.secrets.Database.delete_connnection('testdb')
    print(list_connection_response)

Example output:

.. testoutput:: Database_secrets

    [needs output]

Reset Connection
----------------

.. automethod:: hvac.api.secrets_engines.Database.reset_connection
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    reset_connnection_response = client.secrets.Database.reset_connnection('testdb')
    print(list_connection_response)

Example output:

.. testoutput:: Database_secrets

    [needs output]

Create Role
------------------------

.. automethod:: hvac.api.secrets_engines.Database.create_role
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    create_role_response = client.secrets.database.create_role(
        name="hvac_doctest",
        db_name="hvac_doctest",
        creation_statements=" [ need statements here ] ",
    )



Read role
------------

.. automethod:: hvac.api.secrets_engines.Database.read_role
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    read_response = client.secrets.Database.read_role('hvac-doctest')

List roles
-------------

.. automethod:: hvac.api.secrets_engines.Database.list_roles
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    list_response = client.secrets.Database.list_roles()

Delete role
--------------

.. automethod:: hvac.api.secrets_engines.Database.delete_role
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    delete_response = client.secrets.Database.delete_role(name='hvac-doctest')


Generate Credentials
----------------------------

.. automethod:: hvac.api.secrets_engines.Database.generate_credentials
   :noindex:

Examples
````````

.. testcode:: Database_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    key_response = client.secrets.Database.generate_credentials('hvac-doctest')


.. testcleanup:: Database_secrets

    client.sys.disable_secrets_engine(path='Database')

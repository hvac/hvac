GCP
===

.. contents::
   :local:
   :depth: 1

.. testsetup:: gcp_secrets

    from requests_mock import ANY

    client.sys.enable_secrets_engine('gcp')

    # mock out external calls that are difficult to support in test environments
    mock_urls = {
        'https://127.0.0.1:8200/v1/gcp/config/rotate-root': 'POST',
        'https://127.0.0.1:8200/v1/gcp/rolesets': 'LIST',
        'https://127.0.0.1:8200/v1/gcp/roleset/hvac-doctest': ANY,
        'https://127.0.0.1:8200/v1/gcp/roleset/hvac-doctest/rotate': 'POST',
        'https://127.0.0.1:8200/v1/gcp/roleset/hvac-doctest/rotate-key': 'POST',
        'https://127.0.0.1:8200/v1/gcp/token/hvac-doctest': 'GET',
        'https://127.0.0.1:8200/v1/gcp/key/hvac-doctest': 'POST',
        'https://127.0.0.1:8200/v1/gcp/static-account/hvac-doctest': ANY,
        'https://127.0.0.1:8200/v1/gcp/static-account/hvac-doctest/rotate-key': 'POST',
        'https://127.0.0.1:8200/v1/gcp/static-accounts': 'LIST',
        'https://127.0.0.1:8200/v1/gcp/static-account/hvac-doctest/token': 'GET',
        'https://127.0.0.1:8200/v1/gcp/static-account/hvac-doctest/key': 'POST',
        'https://127.0.0.1:8200/v1/gcp/impersonated-account/hvac-doctest': ANY,
        'https://127.0.0.1:8200/v1/gcp/impersonated-accounts': 'LIST',
        'https://127.0.0.1:8200/v1/gcp/impersonated-account/hvac-doctest/token': 'GET',
    }
    for mock_url, method in mock_urls.items():
        mocker.register_uri(
            method=method,
            url=mock_url,
            json=dict(),
        )

Configure
---------

.. automethod:: hvac.api.secrets_engines.Gcp.configure
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')


    credentials = test_utils.load_config_file('example.jwt.json')
    configure_response = client.secrets.gcp.configure(
        credentials=credentials,
        max_ttl=3600,
    )
    print(configure_response)

Example output:

.. testoutput:: gcp_secrets

    <Response [204]>

Rotate Root Credentials
-----------------------

.. automethod:: hvac.api.secrets_engines.Gcp.rotate_root_credentials
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    rotate_response = client.secrets.gcp.rotate_root_credentials()

Read Config
-----------

.. automethod:: hvac.api.secrets_engines.Gcp.read_config
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    read_config_response = client.secrets.gcp.read_config()
    print('Max TTL for GCP secrets engine set to: {max_ttl}'.format(max_ttl=read_config_response['data']['max_ttl']))

Example output:

.. testoutput:: gcp_secrets

    Max TTL for GCP secrets engine set to: 3600

Create Or Update Roleset
------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.create_or_update_roleset
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')


    bindings = """
        resource "//cloudresourcemanager.googleapis.com/project/some-gcp-project-id" {
          roles = [
            "roles/viewer"
          ],
        }
    """
    token_scopes = [
        'https://www.googleapis.com/auth/cloud-platform',
        'https://www.googleapis.com/auth/bigquery',
    ]

    roleset_response = client.secrets.gcp.create_or_update_roleset(
        name='hvac-doctest',
        project='some-gcp-project-id',
        bindings=bindings,
        token_scopes=token_scopes,
    )

Rotate Roleset Account
----------------------

.. automethod:: hvac.api.secrets_engines.Gcp.rotate_roleset_account
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    rotate_response = client.secrets.gcp.rotate_roleset_account(name='hvac-doctest')

Rotate Roleset Account Key
--------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.rotate_roleset_account_key
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    rotate_response = client.secrets.gcp.rotate_roleset_account_key(name='hvac-doctest')

Read Roleset
------------

.. automethod:: hvac.api.secrets_engines.Gcp.read_roleset
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    read_response = client.secrets.gcp.read_roleset(name='hvac-doctest')

List Rolesets
-------------

.. automethod:: hvac.api.secrets_engines.Gcp.list_rolesets
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    list_response = client.secrets.gcp.list_rolesets()

Delete Roleset
--------------

.. automethod:: hvac.api.secrets_engines.Gcp.delete_roleset
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    delete_response = client.secrets.gcp.delete_roleset(name='hvac-doctest')


Generate Oauth2 Access Token
----------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.generate_oauth2_access_token
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    token_response = client.secrets.gcp.generate_oauth2_access_token(roleset='hvac-doctest')

Generate Service Account Key
----------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.generate_service_account_key
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    key_response = client.secrets.gcp.generate_service_account_key(roleset='hvac-doctest')

Create Or Update Static Account
-------------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.create_or_update_static_account
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    create_response = client.secrets.gcp.create_or_update_static_account(
      name="hvac-doctest",
      service_account_email="hvac-doctest@some-gcp-project-id.iam.gserviceaccount.com",
      secret_type="access_token",
      token_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )

Rotate Static Account Key
-------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.rotate_static_account_key
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    rotate_response = client.secrets.gcp.rotate_static_account_key(name="hvac-doctest")

Read Static Account
-------------------

.. automethod:: hvac.api.secrets_engines.Gcp.read_static_account
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    read_response = client.secrets.gcp.read_static_account(name="hvac-doctest")

List Static Accounts
--------------------

.. automethod:: hvac.api.secrets_engines.Gcp.list_static_accounts
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    list_response = client.secrets.gcp.list_static_accounts()

Delete Static Account
---------------------

.. automethod:: hvac.api.secrets_engines.Gcp.delete_static_account
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    delete_response = client.secrets.gcp.delete_static_account(name="hvac-doctest")

Generate Static Account OAuth2 Access Token
-------------------------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.generate_static_account_oauth2_access_token
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    token_response = client.secrets.gcp.generate_static_account_oauth2_access_token(
      name="hvac-doctest",
    )

Generate Static Account Service Account Key
-------------------------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.generate_static_account_service_account_key
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    key_response = client.secrets.gcp.generate_static_account_service_account_key(
      name="hvac-doctest",
    )

Create Or Update Impersonated Account
-------------------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.create_or_update_impersonated_account
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    create_response = client.secrets.gcp.create_or_update_impersonated_account(
      name="hvac-doctest",
      service_account_email="hvac-doctest@some-gcp-project-id.iam.gserviceaccount.com",
      token_scopes=["https://www.googleapis.com/auth/cloud-platform"],
      ttl='4h'
    )

Read Impersonated Account
-------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.read_impersonated_account
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    read_response = client.secrets.gcp.read_impersonated_account(name="hvac-doctest")

List Impersonated Accounts
--------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.list_impersonated_accounts
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    list_response = client.secrets.gcp.list_impersonated_accounts()

Delete Impersonated Account
---------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.delete_impersonated_account
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    delete_response = client.secrets.gcp.delete_impersonated_account(name="hvac-doctest")

Generate Impersonated Account OAuth2 Access Token
-------------------------------------------------

.. automethod:: hvac.api.secrets_engines.Gcp.generate_impersonated_account_oauth2_access_token
   :noindex:

Examples
````````

.. testcode:: gcp_secrets

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    token_response = client.secrets.gcp.generate_impersonated_account_oauth2_access_token(
      name="hvac-doctest",
    )

.. testcleanup:: gcp_secrets

    client.sys.disable_secrets_engine(path='gcp')
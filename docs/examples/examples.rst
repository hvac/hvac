Examples
========

.. toctree::
   :maxdepth: 4

   audit
   aws
   sys


Authenticate to different auth backends
---------------------------------------

.. code:: python

    # Token
    client.token = 'MY_TOKEN'
    assert client.is_authenticated() # => True

    # App ID
    client.auth_app_id('MY_APP_ID', 'MY_USER_ID')

    # App Role
    client.auth_approle('MY_ROLE_ID', 'MY_SECRET_ID')

    # AWS (IAM)
    client.auth_aws_iam('MY_AWS_ACCESS_KEY_ID', 'MY_AWS_SECRET_ACCESS_KEY')
    client.auth_aws_iam('MY_AWS_ACCESS_KEY_ID', 'MY_AWS_SECRET_ACCESS_KEY', 'MY_AWS_SESSION_TOKEN')
    client.auth_aws_iam('MY_AWS_ACCESS_KEY_ID', 'MY_AWS_SECRET_ACCESS_KEY', role='MY_ROLE')

    import boto3
    session = boto3.Session()
    credentials = session.get_credentials()
    client.auth_aws_iam(credentials.access_key, credentials.secret_key, credentials.token)

    # GitHub
    client.auth_github('MY_GITHUB_TOKEN')

    # GCP (from GCE instance)
    import requests

    VAULT_ADDR="https://vault.example.com:8200"
    ROLE="example"
    AUDIENCE_URL =  VAULT_ADDR + "/vault/" + ROLE
    METADATA_HEADERS = {'Metadata-Flavor': 'Google'}
    FORMAT = 'full'

    url = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={}&format={}'.format(AUDIENCE_URL, FORMAT)
    r = requests.get(url, headers=METADATA_HEADERS)
    client.auth_gcp(ROLE, r.text)

    # Kubernetes (from k8s pod)
    f = open('/var/run/secrets/kubernetes.io/serviceaccount/token')
    jwt = f.read()
    client.auth_kubernetes("example", jwt)

    # LDAP, Username & Password
    client.auth_ldap('MY_USERNAME', 'MY_PASSWORD')
    client.auth_userpass('MY_USERNAME', 'MY_PASSWORD')

    # TLS
    client = Client(cert=('path/to/cert.pem', 'path/to/key.pem'))
    client.auth_tls()

    # Non-default mount point (available on all auth types)
    client.auth_userpass('MY_USERNAME', 'MY_PASSWORD', mount_point='CUSTOM_MOUNT_POINT')

    # Authenticating without changing to new token (available on all auth types)
    result = client.auth_github('MY_GITHUB_TOKEN', use_token=False)
    print(result['auth']['client_token']) # => u'NEW_TOKEN'

    # Custom or unsupported auth type
    params = {
        'username': 'MY_USERNAME',
        'password': 'MY_PASSWORD',
        'custom_param': 'MY_CUSTOM_PARAM',
    }

    result = client.auth('/v1/auth/CUSTOM_AUTH/login', json=params)

    # Logout
    client.logout()

Manage tokens
-------------

.. code:: python

    token = client.create_token(policies=['root'], lease='1h')

    current_token = client.lookup_token()
    some_other_token = client.lookup_token('xxx')

    client.revoke_token('xxx')
    client.revoke_token('yyy', orphan=True)

    client.revoke_token_prefix('zzz')

    client.renew_token('aaa')

Managing tokens using accessors
-------------------------------

.. code:: python

    token = client.create_token(policies=['root'], lease='1h')
    token_accessor = token['auth']['accessor']

    same_token = client.lookup_token(token_accessor, accessor=True)
    client.revoke_token(token_accessor, accessor=True)

Wrapping/unwrapping a token
---------------------------

.. code:: python

    wrap = client.create_token(policies=['root'], lease='1h', wrap_ttl='1m')
    result = self.client.unwrap(wrap['wrap_info']['token'])

Manipulate auth backends
------------------------

.. code:: python

    backends = client.list_auth_backends()

    client.enable_auth_backend('userpass', mount_point='customuserpass')
    client.disable_auth_backend('github')

Manipulate secret backends
--------------------------

.. code:: python

    backends = client.list_secret_backends()

    client.enable_secret_backend('aws', mount_point='aws-us-east-1')
    client.disable_secret_backend('mysql')

    client.tune_secret_backend('generic', mount_point='test', default_lease_ttl='3600s', max_lease_ttl='8600s')
    client.get_secret_backend_tuning('generic', mount_point='test')

    client.remount_secret_backend('aws-us-east-1', 'aws-east')

Manipulate policies
-------------------

.. code:: python

    policies = client.list_policies() # => ['root']

    policy = """
    path "sys" {
      policy = "deny"
    }

    path "secret" {
      policy = "write"
    }

    path "secret/foo" {
      policy = "read"
    }
    """

    client.set_policy('myapp', policy)

    client.delete_policy('oldthing')

    policy = client.get_policy('mypolicy')

    # Requires pyhcl to automatically parse HCL into a Python dictionary
    policy = client.get_policy('mypolicy', parse=True)

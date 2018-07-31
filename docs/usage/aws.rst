AWS Authentication Backend
==========================

Authentication
--------------

IAM authentication method:

.. code:: python

    client.auth_aws_iam('MY_AWS_ACCESS_KEY_ID', 'MY_AWS_SECRET_ACCESS_KEY')
    client.auth_aws_iam('MY_AWS_ACCESS_KEY_ID', 'MY_AWS_SECRET_ACCESS_KEY', 'MY_AWS_SESSION_TOKEN')
    client.auth_aws_iam('MY_AWS_ACCESS_KEY_ID', 'MY_AWS_SECRET_ACCESS_KEY', role='MY_ROLE')

    import boto3
    session = boto3.Session()
    credentials = session.get_credentials()
    client.auth_aws_iam(credentials.access_key, credentials.secret_key, credentials.token)

AWS Secret Backend
==================

To be filled in.

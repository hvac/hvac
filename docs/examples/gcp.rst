GCP Auth Backend
================

Authentication
--------------

.. code:: python

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

GCP Secret Backend
==================

To be filled in.

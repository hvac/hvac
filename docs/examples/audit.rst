Manipulate audit backends
-------------------------

.. code:: python

    backends = client.list_audit_backends()

    options = {
        'path': '/tmp/vault.log',
        'log_raw': True,
    }

    client.enable_audit_backend('file', options=options, name='somefile')
    client.disable_audit_backend('oldfile')

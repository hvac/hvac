
Userpass
========

Authentication
--------------

:py:meth:`hvac.api.auth_methods.Userpass.login`

.. code:: python

    import hvac
    client = hvac.Client()


    client.auth.userpass.login(
        username='<some_username>',
        password='<username_password>',
    )

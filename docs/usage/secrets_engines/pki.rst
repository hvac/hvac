PKI
===

Read CA Certificate
-------------------

:py:meth:`hvac.api.secrets_engines.pki.read_ca_certificate`

.. code:: python

	import hvac
	client = hvac.Client()

        read_ca_certificate_response = client.secrets.pki.read_ca_certificate()
        print('Current PKI CA Certificate: {}'.format(read_ca_certificate_response))


Read CA Certificate Chain
-------------------------

:py:meth:`hvac.api.secrets_engines.pki.read_ca_certificate_chain`

.. code:: python

	import hvac
	client = hvac.Client()

        read_ca_certificate_chain_response = client.secrets.pki.read_ca_certificate_chain()
        print('Current PKI CA Certificate Chain: {}'.format(read_ca_certificate_chain_response))


Read Certificate
----------------

:py:meth:`hvac.api.secrets_engines.pki.read_certificate`

.. code:: python

	import hvac
	client = hvac.Client()

        read_certificate_response = client.secrets.pki.read_certificate(serial='crl')
        print('Current PKI CRL: {}'.format(read_certificate_response))


List Certificates
-----------------

:py:meth:`hvac.api.secrets_engines.pki.list_certificates`

.. code:: python

	import hvac
	client = hvac.Client()

        list_certificate_response = client.secrets.pki.list_certificates()
        print('Current certificates (serial numbers): {}'.format(list_certificate_response))


Submit CA Information
---------------------

:py:meth:`hvac.api.secrets_engines.pki.submit_ca_information`

.. code:: python

	import hvac
	client = hvac.Client()

        submit_ca_information_response = client.secrets.pki.submit_ca_information(
        '-----BEGIN RSA PRIVATE KEY-----\n...\n-----END CERTIFICATE-----'
        )


Read CRL Configuration
----------------------

:py:meth:`hvac.api.secrets_engines.pki.read_crl_configuration`

.. code:: python

	import hvac
	client = hvac.Client()

        read_crl_configuration_response = client.secrets.pki.read_crl_configuration()
        print('CRL configuration: {}'.format(read_crl_configuration_response))


Set CRL Configuration
---------------------

:py:meth:`hvac.api.secrets_engines.pki.set_crl_configuration`

.. code:: python

	import hvac
	client = hvac.Client()

        set_crl_configuration_response = client.secrets.pki.set_crl_configuration(
           expiry='72h',
           disable=False
        )


Read URLs
---------

:py:meth:`hvac.api.secrets_engines.pki.read_urls`

.. code:: python

	import hvac
	client = hvac.Client()

        read_urls_response = client.secrets.pki.read_urls()
        print('Get PKI urls: {}'.format(read_urls_response))


Set URLs
--------

:py:meth:`hvac.api.secrets_engines.pki.set_urls`

.. code:: python

	import hvac
	client = hvac.Client()

        set_urls_response = client.secrets.pki.set_urls(
        {
          'issuing_certificates': ['http://127.0.0.1:8200/v1/pki/ca'],
          'crl_distribution_points': ['http://127.0.0.1:8200/v1/pki/crl']
        }
        )


Read CRL
--------

:py:meth:`hvac.api.secrets_engines.pki.read_crl`

.. code:: python

	import hvac
	client = hvac.Client()

        read_crl_response = client.secrets.pki.read_crl()
        print('Current CRL: {}'.format(read_crl_response))


Rotate CRLs
-----------

:py:meth:`hvac.api.secrets_engines.pki.rotate_crl`

.. code:: python

	import hvac
	client = hvac.Client()

        rotate_crl_response = client.secrets.pki.rotate_crl()
        print('Rotate CRL: {}'.format(rotate_crl_response))


Generate Intermediate
---------------------

:py:meth:`hvac.api.secrets_engines.pki.generate_intermediate`

.. code:: python

	import hvac
	client = hvac.Client()

        generate_intermediate_response = client.secrets.pki.generate_intermediate(
            type='exported',
            common_name='Vault integration tests'
        )
        print('Intermediate certificate: {}'.format(generate_intermediate_response))


Set Signed Intermediate
-----------------------

:py:meth:`hvac.api.secrets_engines.pki.set_signed_intermediate`

.. code:: python

	import hvac
	client = hvac.Client()

        set_signed_intermediate_response = client.secrets.pki.set_signed_intermediate(
            '-----BEGIN CERTIFICATE...'
        )


Generate Certificate
--------------------

:py:meth:`hvac.api.secrets_engines.pki.generate_certificate`

.. code:: python

	import hvac
	client = hvac.Client()

        generate_certificate_response = client.secrets.pki.generate_certificate(
           name='myrole',
           common_name='test.example.com'
        )
        print('Certificate: {}'.format(generate_certificate_response))


Revoke Certificate
------------------

:py:meth:`hvac.api.secrets_engines.pki.revoke_certificate`

.. code:: python

	import hvac
	client = hvac.Client()

        revoke_certificate_response = client.secrets.pki.revoke_certificate(
           serial_number='39:dd:2e...'
        )
        print('Certificate: {}'.format(revoke_certificate_response))


Create/Update Role
------------------

:py:meth:`hvac.api.secrets_engines.pki.create_or_update_role`

.. code:: python

	import hvac
	client = hvac.Client()

        create_or_update_role_response = client.secrets.pki.create_or_update_role(
           'mynewrole',
           {
              'ttl': '72h',
              'allow_localhost': 'false'
           }
        )
        print('New role: {}'.format(create_or_update_role_response))


Read Role
---------

:py:meth:`hvac.api.secrets_engines.pki.read_role`

.. code:: python

	import hvac
	client = hvac.Client()

        read_role_response = client.secrets.pki.read_role('myrole')
        print('Role definition: {}'.format(read_role_response))


List Roles
----------

:py:meth:`hvac.api.secrets_engines.pki.list_roles`

.. code:: python

	import hvac
	client = hvac.Client()

        list_roles_response = client.secrets.pki.list_roles()
        print('List of available roles: {}'.format(list_roles_response))


Delete Role
-----------

:py:meth:`hvac.api.secrets_engines.pki.delete_role`

.. code:: python

	import hvac
	client = hvac.Client()

        delete_role_response = client.secrets.pki.delete_role('role2delete')


Generate Root
-------------

:py:meth:`hvac.api.secrets_engines.pki.generate_root`

.. code:: python

	import hvac
	client = hvac.Client()

        generate_root_response = client.secrets.pki.generate_root(
           type='exported',
           common_name='New root CA'
        )
        print('New root CA: {}'.format(generate_root_response))


Delete Root
-----------

:py:meth:`hvac.api.secrets_engines.pki.delete_root`

.. code:: python

	import hvac
	client = hvac.Client()

        delete_root_response = client.secrets.pki.delete_root()


Sign Intermediate
-----------------

:py:meth:`hvac.api.secrets_engines.pki.sign_intermediate`

.. code:: python

	import hvac
	client = hvac.Client()

        sign_intermediate_response = client.secrets.pki.sign_intermediate(
            csr='....',
            common_name='example.com',
        )
        print('Signed certificate: {}'.format(sign_intermediate_response))


Sign Self-Issued
----------------

:py:meth:`hvac.api.secrets_engines.pki.sign_self_issued`

.. code:: python

	import hvac
	client = hvac.Client()

        sign_self_issued_response = client.secrets.pki.sign_self_issued(
           certificate='...'
        )
        print('Signed certificate: {}'.format(sign_self_issued_response))


Sign Certificate
----------------

:py:meth:`hvac.api.secrets_engines.pki.sign_certificate`

.. code:: python

	import hvac
	client = hvac.Client()

        sign_certificate_response = client.secrets.pki.sign_certificate(
           name='myrole',
           csr='...',
           common_name='example.com'
        )
        print('Signed certificate: {}'.format(sign_certificate_response))


Sign Verbatim
-------------

:py:meth:`hvac.api.secrets_engines.pki.sign_verbatim`

.. code:: python

	import hvac
	client = hvac.Client()

        sign_verbatim_response = client.secrets.pki.sign_verbatim(
           name='myrole',
           csr='...'
        )
        print('Signed certificate: {}'.format(sign_verbatim_response))


Tidy
----

:py:meth:`hvac.api.secrets_engines.pki.tidy`

.. code:: python

	import hvac
	client = hvac.Client()

        tidy_response = client.secrets.pki.tidy()



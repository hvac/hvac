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

        read_ca_certificate_chain_chain_response = self.client.secrets.pki.read_ca_certificate_chain_chain()
        print('Current PKI CA Certificate Chain: {}'.format(read_ca_certificate_chain_response))


Read Certificate
----------------

:py:meth:`hvac.api.secrets_engines.pki.read_certificate`

.. code:: python

	import hvac
	client = hvac.Client()

        read_certificate_response = self.client.secrets.pki.read_certificate(serial='crl')
        print('Current PKI CRL: {}'.format(read_certificate_response))

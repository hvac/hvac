Advanced Usage
==============

.. contents::
   :local:
   :depth: 1

Making Use of Private CA
------------------------

There is a not uncommon use case of people deploying Hashicorp Vault with a private certificate authority. Unfortunately the `requests` module does not make use of the system CA certificates. Instead of disabling SSL verification you can make use of the requests' `verify` parameter.

As `documented in the advanced usage section for requests`_ this variable can point to a file that is comprised of all CA certificates you may wish to use. This can be a single private CA, or an existing list of root certificates with the private appended to the end. The following example shows how to achieve this:

.. code::

	$ cp "$(python -c 'import certifi;print certifi.where();')" /tmp/bundle.pem
	$ cat /path/to/custom.pem >> /tmp/bundle.pem

You then use hvac's Client.session and requests.Session() to pass the new CA bundle to hvac.

.. code:: python

	import os

	import hvac
	import requests


	def get_vault_client(vault_url=VAULT_URL, certs=VAULT_CERTS):
		"""
		Instantiates a hvac / vault client.
		:param vault_url: string, protocol + address + port for the vault service
		:param certs: tuple, Optional tuple of self-signed certs to use for verification
			with hvac's requests adapter.
		:return: hvac.Client
		"""
		logger.debug('Retrieving a vault (hvac) client...')
		vault_client = hvac.Client(
			url=vault_url,
			cert=certs,
		)
		if certs:
		# When use a self-signed certificate for the vault service itself, we need to
		# include our local ca bundle here for the underlying requests module.
			rs = requests.Session()
			vault_client.session = rs
			rs.verify = certs

		vault_client.token = load_vault_token(vault_client)

		if not vault_client.is_authenticated():
			error_msg = 'Unable to authenticate to the Vault service'
			raise hvac.exceptions.Unauthorized(error_msg)

		return vault_client

.. _documented in the advanced usage section for requests: https://requests.readthedocs.io/en/master/user/advanced/#ssl-cert-verification

If only using the certificate authority for trust, not authentication, SSL verification can be set using the `verify` parameter.

This configures the client to trust the connection only if the certificate received is signed by a CA in that bundle:

.. code:: python

	vault_client = hvac.Client(
		url=vault_url,
		verify='/etc/ssl/my-ca-bundle'
	)

.. _documented in the advanced usage section for requests: https://requests.readthedocs.io/en/master/user/advanced/#ssl-cert-verification

Custom Requests / HTTP Adapter
------------------------------

Custom Adapters
***************

.. versionadded:: 0.6.2

Calls to the `requests module`_. (which provides the methods hvac utilizes to send HTTP/HTTPS request to Vault instances) were extracted from the :class:`Client <hvac.v1.Client>` class and moved to a newly added :meth:`hvac.adapters` module. The :class:`Client <hvac.v1.Client>` class itself defaults to an instance of the :class:`JSONAdapter <hvac.adapters.JSONAdapter>` class for its :attr:`_adapter <hvac.v1.Client._adapter>` private attribute attribute if no adapter argument is provided to its :meth:`constructor <hvac.v1.Client.__init__>`. This attribute provides an avenue for modifying the manner in which hvac completes request. To enable this type of customization, implement a class of type :meth:`hvac.adapters.Adapter`, override its abstract methods, and pass this custom class to the adapter argument of the :meth:`Client constructor <hvac.v1.Client.__init__>`

.. _requests module: http://requests.readthedocs.io/en/master/

Retrying Failed Requests
************************

Requests to Vault, like any other HTTP request, should be thoughtfully retried for the best experience. For Vault, this is also important for eventual consistency, where Vault will return status ``412`` `when it cannot complete a request due to data that is not yet available on the node where the request was made <https://developer.hashicorp.com/vault/api-docs#412>`_.

We usually also want to retry ``5xx`` status codes.

The ``hvac`` :class:`Client <hvac.v1.Client>` class supports providing a custom ``Session`` object to its constructor, and through the use of the ``urllib3.util.Retry`` `class <https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html#urllib3.util.Retry>`_ we can fully configure how retries are performed.

.. code:: python

	from hvac import Client
	from urllib3.util import Retry
	from requests import Session
	from requests.adapters import HTTPAdapter

	adapter = HTTPAdapter(max_retries=Retry(
		total=3,
		backoff_factor=0.1,
		status_forcelist=[412, 500, 502, 503],
		raise_on_status=False,
	))
	session = requests.Session()
	session.mount("http://", adapter)
	session.mount("https://", adapter)

	client = Client(url='https://vault.example.com', session=session)


Here we will cover the options shown. See the `full Retry class documentation <https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html#urllib3.util.Retry>`_ for all of the things that can be customized.

In the example, ``total`` refers to the total number of retries that will be performed.

``backoff_factor`` allows for a non-linear delay between retries, with the formula for how long to sleep being: ``{backoff factor} * (2 ** ({number of total retries} - 1))`` (in seconds). This helps prevent retrying too quickly, which mitigates worsening a server overload problem, and prevents an eventual failure if time-based errors are not given enough time to resolve themselves (like eventual consistency failures). Adjust this as needed in your environment.

``status_forcelist`` is a list of HTTP status codes that should be retried. See `Vault HTTP Status Codes <https://developer.hashicorp.com/vault/api-docs#http-status-codes>`_ for a list of which codes Vault returns and in what circumstances.

``raise_on_status`` tells the ``Retry`` class whether or not to raise its own exceptions when retries are exhausted. In the case of ``hvac`` **it is important to set this to** ``False`` because ``hvac``'s own exceptions are raised based on the exceptions returned by the `requests module`_. If this is set to ``True``, your application will receive different exceptions, and behavior of ``hvac`` methods may not be consistent.

Allowed methods
^^^^^^^^^^^^^^^

Not shown above is the ``allowed_methods`` option for the ``Retry`` class. This controls which HTTP methods should be retried.

The `default value <https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html#urllib3.util.Retry.DEFAULT_ALLOWED_METHODS>`_ is ``frozenset({'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PUT', 'TRACE'})``. As described in the documentation:

	By default, we only retry on methods which are considered to be idempotent (multiple requests with the same parameters end with the same state).

This means that ``POST`` and ``PATCH`` requests will not be retried by default; you may want to retry those in some cases if you know the operation is idempotent, or you otherwise do not need to be concerned with changing state more than once, but this should be done with caution.

Multiple ``Client`` instances with different retry settings could be used to control that, or you may wish to handle retries on specific methods by catching exceptions and retrying the ``hvac`` calls within your own code.

Vault Agent Unix Socket Listener
--------------------------------

hvac does not currently offer direct support of requests to a `Vault agent process configured with a unix socket listener <https://github.com/hashicorp/vault/pull/6220/>`_. However this use case can be handled with the help of the `requests_unixsocket module <https://pypi.org/project/requests-unixsocket/>`_. To accomplish this, first ensure the module is available (e.g. `pip install requests_unixsocket`), and then instantiate the :class:`Client <hvac.v1.Client>` class in the following manner:


.. code:: python

	import urllib.parse

	import requests_unixsocket
	import hvac

	vault_agent_socket_path = '/var/run/vault/agent.sock'
	socket_url = 'http+unix://{encoded_path}'.format(
		encoded_path=urllib.parse.quote(vault_agent_socket_path, safe='')
	)
	socket_session = requests_unixsocket.Session()
	client = hvac.Client(
		url=socket_url,
		session=socket_session,
	)
	print(client.secrets.kv.read_secret_version(path='some-secret'))

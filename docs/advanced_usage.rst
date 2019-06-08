Advanced Usage
==============

Making Use of Private CA
------------------------

There is a not uncommon use case of people deploying Hashicorp Vault with a private certificate authority. Unfortunately the `requests` module does not make use of the system CA certificates. Instead of disabling SSL verification you can make use of the `REQUESTS_CA_BUNDLE` environment variable.

As `documented in the advanced usage section for requests`_ this environment variable should point to a file that is comprised of all CA certificates you may wish to use. This can be a single private CA, or an existing list of root certificates with the private appended to the end. The following example shows how to achieve this:

.. code:: python

	$ cp "$(python -c 'import certifi;print certifi.where();')" /tmp/bundle.pem
	$ cat /path/to/custom.pem >> /tmp/bundle.pem
	$ export REQUESTS_CA_BUNDLE=/tmp/bundle.pem

Alternative, this envrionmental variable can be set via the `os` module in-line with other Python statements. The following example would be one way to manage this configuration on a Ubuntu host:

.. code:: python

	import os

	import hvac


	def get_vault_client(vault_url=VAULT_URL, certs=VAULT_CERTS):
		"""
		Instantiates a hvac / vault client.
		:param vault_url: string, protocol + address + port for the vault service
		:param certs: tuple, Optional tuple of self-signed certs to use for verification
			with hvac's requests adapater.
		:return: hvac.Client
		"""
		logger.debug('Retrieving a vault (hvac) client...')
		if certs:
			# When use a self-signed certificate for the vault service itself, we need to
			# include our local ca bundle here for the underlying requests module.
			os.environ['REQUESTS_CA_BUNDLE'] = '/etc/ssl/certs/ca-certificates.crt'

		vault_client = hvac.Client(
			url=vault_url,
			cert=certs,
		)

		vault_client.token = load_vault_token(vault_client)

		if not vault_client.is_authenticated():
			error_msg = 'Unable to authenticate to the Vault service'
			raise hvac.exceptions.Unauthorized(error_msg)

		return vault_client

.. _documented in the advanced usage section for requests: http://docs.python-requests.org/en/master/user/advanced/

Custom Requests / HTTP Adapter
------------------------------

.. versionadded:: 0.6.2

Calls to the `requests module`_. (which provides the methods hvac utilizes to send HTTP/HTTPS request to Vault instances) were extracted from the :class:`Client <hvac.v1.Client>` class and moved to a newly added :meth:`hvac.adapters` module. The :class:`Client <hvac.v1.Client>` class itself defaults to an instance of the :class:`Request <hvac.adapters.Request>` class for its :attr:`_adapter <hvac.v1.Client._adapter>` private attribute attribute if no adapter argument is provided to its :meth:`constructor <hvac.v1.Client.__init__>`. This attribute provides an avenue for modifying the manner in which hvac completes request. To enable this type of customization, implement a class of type :meth:`hvac.adapters.Adapter`, override its abstract methods, and pass an instance of this custom class to the adapter argument of the :meth:`Client constructor <hvac.v1.Client.__init__>`

.. _requests module: http://requests.readthedocs.io/en/master/

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


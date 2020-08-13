Advanced Usage
==============

.. contents::
   :local:
   :depth: 1

Making Use of Private CA
------------------------

There is a not uncommon use case of people deploying Hashicorp Vault with a private certificate authority. Unfortunately the `requests` module does not make use of the system CA certificates. Instead of disabling SSL verification you can make use of the `REQUESTS_CA_BUNDLE` environment variable.

As `documented in the advanced usage section for requests`_ this environment variable should point to a file that is comprised of all CA certificates you may wish to use. This can be a single private CA, or an existing list of root certificates with the private appended to the end. The following example shows how to achieve this:

.. code::

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

Calls to the `requests module`_. (which provides the methods hvac utilizes to send HTTP/HTTPS request to Vault instances) were extracted from the :class:`Client <hvac.v1.Client>` class and moved to a newly added :meth:`hvac.adapters` module. The :class:`Client <hvac.v1.Client>` class itself defaults to an instance of the :class:`JSONAdapter <hvac.adapters.JSONAdapter>` class for its :attr:`_adapter <hvac.v1.Client._adapter>` private attribute attribute if no adapter argument is provided to its :meth:`constructor <hvac.v1.Client.__init__>`. This attribute provides an avenue for modifying the manner in which hvac completes request. To enable this type of customization, implement a class of type :meth:`hvac.adapters.Adapter`, override its abstract methods, and pass this custom class to the adapter argument of the :meth:`Client constructor <hvac.v1.Client.__init__>`

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



Using Vault behind Google IAP
--------------------------------
Official Google product page:  https://cloud.google.com/iap

Vault instances secured behind Google IAP enjoy an extra level of protection due to the Google Cloud Platform role required to access the web application. In order to access your vault instance each request must contain a valid Google-issued OpenID Connect token in the authorization header via bearer tokens.

Rather than build a static feature to allow only Google IAP it was decided to build an advanced_function parameter that could support a plugable proxy backend.  This was accomplished via passing in a dictionary container a string with the provider name which will need to match a valid key in `ProxyRouter.ADVANCED_PROXIES`

.. code:: python

    advanced_proxy = {
        "provider": "google",
        "payload": {
            "client_id": "your_google_client_id.apps.googleusercontent.com"
        }
    }

    self.client = hvac.Client(url=vault_url, namespace='your_vault_namespace', advanced_proxies=advanced_proxy)

When the adapter is called to complete any request, it will attempt to generate an authorization header. If this call returns None, no action is taken on the request and it continues as normal.

.. code:: python

        # Support for advanced proxies
        auth_header = self.proxy_router.get_request_authorization_header()
        if auth_header is not None:
            headers['Authorization'] = auth_header

Creating you own advanced proxy method is relatively simple. There are two functions that MUST be used in order to maintain compataiblity between plugins.

- self.add_payload()
    - This should add the values required for your proxy to your plugin in order for generated you token to get pass the proxy. In our case this is the client_id for your IAP instance.
- self.generate_auth_token()
    - This function will return a valid token that can simply be passed to the Authorization header in the HTTP request

An other required logic is left up to the developer of the plugin to implement.

.. code:: python

    class NginxProxy:

        def __init__(self):
            self.payload_value1 = None
            self.payload_value2 = None

        def add_payload(self, payload):
            """
            Standard function for all plugins to add the content of the advanced_proxy["payload"] into plugin.
            """
            self.payload_value1 = payload['password']
            self.payload_value2 = payload['username']

        def generate_auth_token(self):
            """
            Returns a valid bearer token.
            This token is then added to the Authorization Header for each request
            :return:
            """
            return f"Bearer {self.payload_value1}:{self.payload_value2}"

The new proxy provider class mapping must be added to this dictionary to ensure only valid values are passed in and acted upon during runtime.

.. code:: python

        self.ADVANCED_PROXIES = {
            "google": GoogleIAP,
        }



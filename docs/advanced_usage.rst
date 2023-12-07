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

Support for HTTP/2 onward with Niquests
---------------------------------------

While unofficial, hvac can speak HTTP/2, and HTTP/3 using the alternative HTTP backend Niquests.
It is made possible thanks to the library backward compatibility with Requests. We can explore
a few possible integrations.

.. warning:: The samples presented in this section is not covered by hvac maintainers. Any issue is to be addressed to Niquests maintainers.

Session
*******

Basically, the fastest way to upgrade the client is:

.. code:: python

    import niquests
    import hvac

    session = niquests.Session()

    client = hvac.Client(
        url='https://vault.example.com',
        session=session,
    )


.. note:: To know more about it, see the `Niquests documentation <https://niquests.readthedocs.io/en/latest/>`_.

Security
********

hvac handles critical operations that can bring undesired eyes into your HTTP interactions.
Fortunately, Niquests enforce some best security practices like OCSP certificate validation and
support encrypted DNS protocols, like but not limited to DNS-over-HTTPS or DNS-over-QUIC.

.. code:: python

    import niquests
    import hvac

    session = niquests.Session(resolver="doh+cloudflare://")

    client = hvac.Client(
        url='https://vault.example.com',
        session=session,
    )

It should get you covered in most cases of advanced attack scenarios. Support for DNSSEC is also automatically
enabled in the given example.

.. note:: To know more about custom resolvers, see the `DNS resolution documentation <https://niquests.readthedocs.io/en/latest/user/quickstart.html#dns-resolution>`_.

Multiplexing
************

You may leverage a multiplexed connection thanks to Niquests native capabilities.
Unfortunately hvac does access the response immediately after receiving it, thus preventing non-blocking IO.

To be able to make concurrent requests using one connection, you will have to override the default adapter.

.. code:: python

    import niquests
    import hvac
    from hvac.adapters import RawAdapter

    class NiquestsAdapter(RawAdapter):

        def __init__(self, base_uri=DEFAULT_URL, token=None, cert=None, verify=True, timeout=30, proxies=None,
                     allow_redirects=True, session=None, namespace=None, ignore_exceptions=False, strict_http=False,
                     request_header=True):
            if not session:
                session = niquests.Session(multiplexed=True)
                session.cert, session.verify, session.proxies = cert, verify, proxies
            else:
                if session.verify:
                    verify = session.verify
                if session.cert:
                    cert = session.cert
                if session.proxies:
                    proxies = session.proxies

            self.base_uri = base_uri
            self.token = token
            self.namespace = namespace
            self.session = session
            self.allow_redirects = allow_redirects
            self.ignore_exceptions = ignore_exceptions
            self.strict_http = strict_http
            self.request_header = request_header

            self._kwargs = {
                "cert": cert,
                "verify": verify,
                "timeout": timeout,
                "proxies": proxies,
            }

        def request(self, method, url, headers=None, raise_exception=True, **kwargs):
            while "//" in url:
                # Vault CLI treats a double forward slash ('//') as a single forward slash for a given path.
                # To avoid issues with the requests module's redirection logic, we perform the same translation here.
                url = url.replace("//", "/")

            url = self.urljoin(self.base_uri, url)

            if not headers:
                headers = {}

            if self.request_header:
                headers["X-Vault-Request"] = "true"

            if self.token:
                headers["X-Vault-Token"] = self.token

            if self.namespace:
                headers["X-Vault-Namespace"] = self.namespace

            wrap_ttl = kwargs.pop("wrap_ttl", None)
            if wrap_ttl:
                headers["X-Vault-Wrap-TTL"] = str(wrap_ttl)

            _kwargs = self._kwargs.copy()
            _kwargs.update(kwargs)

            if self.strict_http and method.lower() in ("list",):
                # Entry point for standard HTTP substitution
                params = _kwargs.get("params", {})
                if method.lower() == "list":
                    method = "get"
                    params.update({"list": "true"})
                _kwargs["params"] = params

            if not self.ignore_exceptions and raise_exception:
                def check_error(resp):
                    nonlocal method, url

                    if not resp.ok:
                        msg = json = text = errors = None

                        try:
                            text = response.text
                        except Exception:
                            pass

                        if "json" in response.headers.get("Content-Type"):
                            try:
                                json = response.json()
                            except Exception:
                                pass
                            else:
                                errors = json.get("errors")

                        if errors is None:
                            msg = text

                        utils.raise_for_error(
                            method,
                            url,
                            response.status_code,
                            msg,
                            errors=errors,
                            text=text,
                            json=json,
                        )

                _kwargs["hooks"] = {
                    "response": [check_error]
                }

            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                allow_redirects=self.allow_redirects,
                **_kwargs
            )

            return response


.. note:: To know more about multiplexing, visit https://niquests.readthedocs.io/en/latest/user/quickstart.html#multiplexed-connection

Then you would use the newly constructed adapter into your hvac client like so:

.. code:: python

    client = hvac.Client(
        url='https://vault.example.com',
        adapter=NiquestsAdapter,
    )


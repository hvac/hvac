Support for HTTP/2 onward with Niquests
---------------------------------------

.. contents::
   :local:
   :depth: 1


While unofficial, ``hvac`` can speak HTTP/2, and HTTP/3 using the alternative HTTP backend `Niquests <https://pypi.org/project/niquests/>`_.
It is made possible thanks to the library backward compatibility with `Requests <https://pypi.org/project/requests/>`_. We can explore
a few possible integrations.

.. warning:: The samples presented in this section is not covered by ``hvac`` maintainers. Any issue is to be addressed to `Niquests maintainers <https://github.com/jawah/niquests/issues>`_.

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

``hvac`` handles critical operations that can bring undesired eyes into your HTTP interactions.
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
Unfortunately ``hvac`` does access the response immediately after receiving it, thus preventing non-blocking IO.

To be able to make concurrent requests using one connection, you will have to override the default adapter.

.. code:: python

    import niquests

    from hvac.adapters import RawAdapter
    from hvac.constants.client import DEFAULT_URL
    from hvac import utils


    class NiquestsAdapter(RawAdapter):

        def __init__(
            self, base_uri=DEFAULT_URL, token=None, cert=None,
            verify=True, timeout=30, proxies=None, allow_redirects=True,
            session=None, namespace=None, ignore_exceptions=False, strict_http=False,
            request_header=True, resolver=None, source_address=None
        ):
            if not session:
                session = niquests.Session(
                    multiplexed=True,
                    resolver=resolver,
                    source_address=source_address,
                )
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
                        msg = json = errors = None

                        text = response.text

                        try:
                            json = response.json()
                        except JSONDecodeError:
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


.. note:: To know more about multiplexing, see the `Multiplexing documentation <https://niquests.readthedocs.io/en/latest/user/quickstart.html#multiplexed-connection>`_.

Then you would use the newly constructed adapter into your ``hvac`` client like so:

.. code:: python

    import hvac

    client = hvac.Client(
        url='https://vault.example.com',
        adapter=NiquestsAdapter,
    )

# coding=utf-8
"""
HTTP Client Library Adapters

"""
from abc import ABCMeta, abstractmethod

import requests
import requests.exceptions

from hvac import utils

DEFAULT_BASE_URI = 'http://localhost:8200'


class Adapter(object):
    """Abstract base class used when constructing adapters for use with the Client class."""
    __metaclass__ = ABCMeta

    def __init__(self, base_uri=DEFAULT_BASE_URI, token=None, cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None, namespace=None, ignore_exceptions=False):
        """Create a new request adapter instance.

        :param base_uri: Base URL for the Vault instance being addressed.
        :type base_uri: str
        :param token: Authentication token to include in requests sent to Vault.
        :type token: str
        :param cert: Certificates for use in requests sent to the Vault instance. This should be a tuple with the
            certificate and then key.
        :type cert: tuple
        :param verify: Either a boolean to indicate whether TLS verification should be performed when sending requests to Vault,
            or a string pointing at the CA bundle to use for verification. See http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification.
        :type verify: Union[bool,str]
        :param timeout: The timeout value for requests sent to Vault.
        :type timeout: int
        :param proxies: Proxies to use when preforming requests.
            See: http://docs.python-requests.org/en/master/user/advanced/#proxies
        :type proxies: dict
        :param allow_redirects: Whether to follow redirects when sending requests to Vault.
        :type allow_redirects: bool
        :param session: Optional session object to use when performing request.
        :type session: request.Session
        :param namespace: Optional Vault Namespace.
        :type namespace: str
        :param ignore_exceptions: If True, _always_ return the response object for a given request. I.e., don't raise an exception
            based on response status code, etc.
        :type ignore_exceptions: bool
        """
        if not session:
            session = requests.Session()

        self.base_uri = base_uri
        self.token = token
        self.namespace = namespace
        self.session = session
        self.allow_redirects = allow_redirects
        self.ignore_exceptions = ignore_exceptions

        self._kwargs = {
            'cert': cert,
            'verify': verify,
            'timeout': timeout,
            'proxies': proxies,
        }

    @staticmethod
    def urljoin(*args):
        """Joins given arguments into a url. Trailing and leading slashes are stripped for each argument.

        :param args: Multiple parts of a URL to be combined into one string.
        :type args: str | unicode
        :return: Full URL combining all provided arguments
        :rtype: str | unicode
        """

        return '/'.join(map(lambda x: str(x).strip('/'), args))

    def close(self):
        """Close the underlying Requests session.
        """
        self.session.close()

    def get(self, url, **kwargs):
        """Performs a GET request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request('get', url, **kwargs)

    def post(self, url, **kwargs):
        """Performs a POST request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request('post', url, **kwargs)

    def put(self, url, **kwargs):
        """Performs a PUT request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request('put', url, **kwargs)

    def delete(self, url, **kwargs):
        """Performs a DELETE request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request('delete', url, **kwargs)

    def list(self, url, **kwargs):
        """Performs a LIST request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request('list', url, **kwargs)

    def head(self, url, **kwargs):
        """Performs a HEAD request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request('head', url, **kwargs)

    def login(self, url, use_token=True, **kwargs):
        """Perform a login request.

        Associated request is typically to a path prefixed with "/v1/auth") and optionally stores the client token sent
            in the resulting Vault response for use by the :py:meth:`hvac.adapters.Adapter` instance under the _adapater
            Client attribute.

        :param url: Path to send the authentication request to.
        :type url: str | unicode
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the the :py:meth:`hvac.adapters.Adapter` instance under the _adapater Client attribute.
        :type use_token: bool
        :param kwargs: Additional keyword arguments to include in the params sent with the request.
        :type kwargs: dict
        :return: The response of the auth request.
        :rtype: requests.Response
        """
        response = self.post(url, **kwargs)

        if use_token:
            self.token = self.get_login_token(response)

        return response

    @abstractmethod
    def get_login_token(self, response):
        """Extracts the client token from a login response.

        :param response: The response object returned by the login method.
        :return: A client token.
        :rtype: str
        """
        return NotImplementedError

    @utils.deprecated_method(
        to_be_removed_in_version='0.9.0',
        new_method=login,
    )
    def auth(self, url, use_token=True, **kwargs):
        return self.login(
            url=url,
            use_token=use_token,
            **kwargs
        )

    @abstractmethod
    def request(self, method, url, headers=None, raise_exception=True, **kwargs):
        """Main method for routing HTTP requests to the configured Vault base_uri. Intended to be implement by subclasses.

        :param method: HTTP method to use with the request. E.g., GET, POST, etc.
        :type method: str
        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param headers: Additional headers to include with the request.
        :type headers: dict
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :param raise_exception: If True, raise an exception via utils.raise_for_error(). Set this parameter to False to
            bypass this functionality.
        :type raise_exception: bool
        :return: The response of the request.
        :rtype: requests.Response
        """
        raise NotImplementedError


class RawAdapter(Adapter):
    """
    The RawAdapter adapter class.
    This adapter adds Vault-specific headers as required and optionally raises exceptions on errors,
    but always returns Response objects for requests.
    """

    def get_login_token(self, response):
        """Extracts the client token from a login response.

        :param response: The response object returned by the login method.
        :type response: requests.Response
        :return: A client token.
        :rtype: str
        """
        response_json = response.json()
        return response_json['auth']['client_token']

    def request(self, method, url, headers=None, raise_exception=True, **kwargs):
        """Main method for routing HTTP requests to the configured Vault base_uri.

        :param method: HTTP method to use with the request. E.g., GET, POST, etc.
        :type method: str
        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param headers: Additional headers to include with the request.
        :type headers: dict
        :param raise_exception: If True, raise an exception via utils.raise_for_error(). Set this parameter to False to
            bypass this functionality.
        :type raise_exception: bool
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        while '//' in url:
            # Vault CLI treats a double forward slash ('//') as a single forward slash for a given path.
            # To avoid issues with the requests module's redirection logic, we perform the same translation here.
            url = url.replace('//', '/')

        url = self.urljoin(self.base_uri, url)

        if not headers:
            headers = {}

        if self.token:
            headers['X-Vault-Token'] = self.token

        if self.namespace:
            headers['X-Vault-Namespace'] = self.namespace

        wrap_ttl = kwargs.pop('wrap_ttl', None)
        if wrap_ttl:
            headers['X-Vault-Wrap-TTL'] = str(wrap_ttl)

        _kwargs = self._kwargs.copy()
        _kwargs.update(kwargs)

        response = self.session.request(
            method=method,
            url=url,
            headers=headers,
            allow_redirects=self.allow_redirects,
            **_kwargs
        )

        if not response.ok and (raise_exception and not self.ignore_exceptions):
            text = errors = None
            if response.headers.get('Content-Type') == 'application/json':
                try:
                    errors = response.json().get('errors')
                except Exception:
                    pass
            if errors is None:
                text = response.text
            utils.raise_for_error(
                method,
                url,
                response.status_code,
                text,
                errors=errors
            )

        return response


class JSONAdapter(RawAdapter):
    """
    The JSONAdapter adapter class.
    This adapter works just like the RawAdapter adapter except that HTTP 200 responses are returned as JSON dicts.
    All non-200 responses are returned as Response objects.
    """

    def get_login_token(self, response):
        """Extracts the client token from a login response.

        :param response: The response object returned by the login method.
        :type response: dict | requests.Response
        :return: A client token.
        :rtype: str
        """
        return response['auth']['client_token']

    def request(self, *args, **kwargs):
        """Main method for routing HTTP requests to the configured Vault base_uri.

        :param args: Positional arguments to pass to RawAdapter.request.
        :type args: list
        :param kwargs: Keyword arguments to pass to RawAdapter.request.
        :type kwargs: dict
        :return: Dict on HTTP 200 with JSON body, otherwise the response object.
        :rtype: dict | requests.Response
        """
        response = super(JSONAdapter, self).request(*args, **kwargs)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                pass

        return response


# Retaining the legacy name
Request = RawAdapter

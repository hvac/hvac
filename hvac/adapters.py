# coding=utf-8
"""
HTTP Client Library Adapters

"""
import logging

import requests
import requests.exceptions

from hvac import utils
from abc import ABCMeta, abstractmethod

logger = logging.getLogger(__name__)

DEFAULT_BASE_URI = 'http://localhost:8200'


class Adapter(object):
    """Abstract base class used when constructing adapters for use with the Client class."""
    __metaclass__ = ABCMeta

    def __init__(self, base_uri=DEFAULT_BASE_URI, token=None, cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None):
        """Create a new request adapter instance.

        :param base_uri: Base URL for the Vault instance being addressed.
        :type base_uri: str
        :param token: Authentication token to include in requests sent to Vault.
        :type token: str
        :param cert: Certificates for use in requests sent to the Vault instance. This should be a tuple with the
            certificate and then key.
        :type cert: tuple
        :param verify: Flag to indicate whether TLS verification should be performed when sending requests to Vault.
        :type verify: bool
        :param timeout: The timeout value for requests sent to Vault.
        :type timeout: int
        :param proxies: Proxies to use when preforming requests.
            See: http://docs.python-requests.org/en/master/user/advanced/#proxies
        :type proxies: dict
        :param allow_redirects: Whether to follow redirects when sending requests to Vault.
        :type allow_redirects: bool
        :param session: Optional session object to use when performing request.
        :type session: request.Session
        """
        if not session:
            session = requests.Session()

        self.base_uri = base_uri
        self.token = token
        self.session = session
        self.allow_redirects = allow_redirects

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
        :type args: basestring
        :return: Full URL combining all provided arguments
        :rtype: basestring
        """

        return '/'.join(map(lambda x: str(x).strip('/'), args))

    def get(self, url, **kwargs):
        """Performs a GET request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: basestring
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
        :type url: basestring
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
        :type url: basestring
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request('put', url, **kwargs)

    def close(self):
        """Close the underlying Requests session.
        """
        self.session.close()

    def delete(self, url, **kwargs):
        """Performs a DELETE request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: basestring
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request('delete', url, **kwargs)

    @abstractmethod
    def request(self, method, url, headers=None, **kwargs):
        raise NotImplemented


class Request(Adapter):
    """The Request adapter class"""

    def request(self, method, url, headers=None, **kwargs):
        """

        :param method: HTTP method to use with the request. E.g., GET, POST, etc.
        :type method: str
        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: basestring
        :param headers: Additional headers to include with the request.
        :type headers: dict
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        url = self.urljoin(self.base_uri, url)

        if not headers:
            headers = {}

        if self.token:
            headers['X-Vault-Token'] = self.token

        wrap_ttl = kwargs.pop('wrap_ttl', None)
        if wrap_ttl:
            headers['X-Vault-Wrap-TTL'] = str(wrap_ttl)

        _kwargs = self._kwargs.copy()
        _kwargs.update(kwargs)

        response = self.session.request(method, url, headers=headers,
                                        allow_redirects=False, **_kwargs)

        # NOTE(ianunruh): workaround for https://github.com/hvac/hvac/issues/51
        while response.is_redirect and self.allow_redirects:
            url = self.urljoin(self.base_uri, response.headers['Location'])
            response = self.session.request(method, url, headers=headers,
                                            allow_redirects=False, **_kwargs)

        if response.status_code >= 400 and response.status_code < 600:
            text = errors = None
            if response.headers.get('Content-Type') == 'application/json':
                errors = response.json().get('errors')
            if errors is None:
                text = response.text
            utils.raise_for_error(response.status_code, text, errors=errors)

        return response

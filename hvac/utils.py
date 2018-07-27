"""
Misc utility functions and constants
"""

import functools
import inspect
import warnings
from textwrap import dedent

from hvac import exceptions


def raise_for_error(status_code, message=None, errors=None):
    """Helper method to raise exceptions based on the status code of a response received back from Vault.

    :param status_code: Status code received in a response from Vault.
    :type status_code: int
    :param message: Optional message to include in a resulting exception.
    :type message: str
    :param errors: Optional errors to include in a resulting exception.
    :type errors: list | str

    :raises: hvac.exceptions.InvalidRequest | hvac.exceptions.Unauthorized | hvac.exceptions.Forbidden |
        hvac.exceptions.InvalidPath | hvac.exceptions.RateLimitExceeded | hvac.exceptions.InternalServerError |
        hvac.exceptions.VaultNotInitialized | hvac.exceptions.VaultDown | hvac.exceptions.UnexpectedError

    """
    if status_code == 400:
        raise exceptions.InvalidRequest(message, errors=errors)
    elif status_code == 401:
        raise exceptions.Unauthorized(message, errors=errors)
    elif status_code == 403:
        raise exceptions.Forbidden(message, errors=errors)
    elif status_code == 404:
        raise exceptions.InvalidPath(message, errors=errors)
    elif status_code == 429:
        raise exceptions.RateLimitExceeded(message, errors=errors)
    elif status_code == 500:
        raise exceptions.InternalServerError(message, errors=errors)
    elif status_code == 501:
        raise exceptions.VaultNotInitialized(message, errors=errors)
    elif status_code == 503:
        raise exceptions.VaultDown(message, errors=errors)
    else:
        raise exceptions.UnexpectedError(message)


def deprecated_method(to_be_removed_in_version, new_method=None):
    """This is a decorator which can be used to mark methods as deprecated. It will result in a warning being emitted
    when the function is used.

    :param to_be_removed_in_version: Version of this module the decorated method will be removed in.
    :type to_be_removed_in_version: str
    :param new_method: Method intended to replace the decorated method. This method's docstrings are included in the
        decorated method's docstring.
    :type new_method: function
    :return: Wrapped function that includes a deprecation warning and update docstrings from the replacement method.
    :rtype: types.FunctionType
    """
    def decorator(method):
        message = "Call to deprecated function '{old_func}'. This method will be removed in version '{version}'".format(
            old_func=method.__name__,
            version=to_be_removed_in_version,
        )
        if new_method:
            message += " Please use the '{method_name}' method on the '{module_name}' class moving forward.".format(
                method_name=new_method.__name__,
                module_name=inspect.getmodule(new_method).__name__
            )

        @functools.wraps(method)
        def new_func(*args, **kwargs):
            warnings.simplefilter('always', DeprecationWarning)  # turn off filter

            warnings.warn(
                message=message,
                category=DeprecationWarning,
                stacklevel=2,
            )
            warnings.simplefilter('default', DeprecationWarning)  # reset filter
            return method(*args, **kwargs)
        if new_method:
            new_func.__doc__ = dedent(
                """\
                {message}
                Docstring content from this method's replacement copied below:
                {new_docstring}
                """.format(
                    message=message,
                    new_docstring=new_method.__doc__,
                )
            )
        else:
            new_func.__doc__ = message
        return new_func
    return decorator

"""
Misc utility functions and constants
"""

import functools
import inspect
import os
import warnings
from textwrap import dedent

import six

from hvac import exceptions


def raise_for_error(method, url, status_code, message=None, errors=None):
    """Helper method to raise exceptions based on the status code of a response received back from Vault.

    :param method: HTTP method of a request to Vault.
    :type method: str
    :param url: URL of the endpoint requested in Vault.
    :type url: str
    :param status_code: Status code received in a response from Vault.
    :type status_code: int
    :param message: Optional message to include in a resulting exception.
    :type message: str
    :param errors: Optional errors to include in a resulting exception.
    :type errors: list | str

    :raises: hvac.exceptions.InvalidRequest | hvac.exceptions.Unauthorized | hvac.exceptions.Forbidden |
        hvac.exceptions.InvalidPath | hvac.exceptions.RateLimitExceeded | hvac.exceptions.InternalServerError |
        hvac.exceptions.VaultNotInitialized | hvac.exceptions.BadGateway | hvac.exceptions.VaultDown |
        hvac.exceptions.UnexpectedError

    """
    if status_code == 400:
        raise exceptions.InvalidRequest(message, errors=errors, method=method, url=url)
    elif status_code == 401:
        raise exceptions.Unauthorized(message, errors=errors, method=method, url=url)
    elif status_code == 403:
        raise exceptions.Forbidden(message, errors=errors, method=method, url=url)
    elif status_code == 404:
        raise exceptions.InvalidPath(message, errors=errors, method=method, url=url)
    elif status_code == 429:
        raise exceptions.RateLimitExceeded(
            message, errors=errors, method=method, url=url
        )
    elif status_code == 500:
        raise exceptions.InternalServerError(
            message, errors=errors, method=method, url=url
        )
    elif status_code == 501:
        raise exceptions.VaultNotInitialized(
            message, errors=errors, method=method, url=url
        )
    elif status_code == 502:
        raise exceptions.BadGateway(message, errors=errors, method=method, url=url)
    elif status_code == 503:
        raise exceptions.VaultDown(message, errors=errors, method=method, url=url)
    else:
        raise exceptions.UnexpectedError(message or errors, method=method, url=url)


def generate_method_deprecation_message(
    to_be_removed_in_version, old_method_name, method_name=None, module_name=None
):
    """Generate a message to be used when warning about the use of deprecated methods.

    :param to_be_removed_in_version: Version of this module the deprecated method will be removed in.
    :type to_be_removed_in_version: str
    :param old_method_name: Deprecated method name.
    :type old_method_name:  str
    :param method_name:  Method intended to replace the deprecated method indicated. This method's docstrings are
        included in the decorated method's docstring.
    :type method_name: str
    :param module_name: Name of the module containing the new method to use.
    :type module_name: str
    :return: Full deprecation warning message for the indicated method.
    :rtype: str
    """
    message = "Call to deprecated function '{old_method_name}'. This method will be removed in version '{version}'".format(
        old_method_name=old_method_name,
        version=to_be_removed_in_version,
    )
    if method_name is not None and module_name is not None:
        message += " Please use the '{method_name}' method on the '{module_name}' class moving forward.".format(
            method_name=method_name,
            module_name=module_name,
        )
    return message


def generate_property_deprecation_message(
    to_be_removed_in_version, old_name, new_name, new_attribute, module_name="Client"
):
    """Generate a message to be used when warning about the use of deprecated properties.

    :param to_be_removed_in_version: Version of this module the deprecated property will be removed in.
    :type to_be_removed_in_version: str
    :param old_name: Deprecated property name.
    :type old_name: str
    :param new_name: Name of the new property name to use.
    :type new_name: str
    :param new_attribute: The new attribute where the new property can be found.
    :type new_attribute: str
    :param module_name: Name of the module containing the new method to use.
    :type module_name: str
    :return: Full deprecation warning message for the indicated property.
    :rtype: str
    """
    message = "Call to deprecated property '{name}'. This property will be removed in version '{version}'".format(
        name=old_name,
        version=to_be_removed_in_version,
    )
    message += " Please use the '{new_name}' property on the '{module_name}.{new_attribute}' attribute moving forward.".format(
        new_name=new_name,
        module_name=module_name,
        new_attribute=new_attribute,
    )
    return message


def getattr_with_deprecated_properties(obj, item, deprecated_properties):
    """Helper method to use in the getattr method of a class with deprecated properties.

    :param obj: Instance of the Class containing the deprecated properties in question.
    :type obj: object
    :param item: Name of the attribute being requested.
    :type item: str
    :param deprecated_properties: List of deprecated properties. Each item in the list is a dict with at least a
        "to_be_removed_in_version" and "client_property" key to be used in the displayed deprecation warning.
    :type deprecated_properties: List[dict]
    :return: The new property indicated where available.
    :rtype: object
    """
    if item in deprecated_properties:
        deprecation_message = generate_property_deprecation_message(
            to_be_removed_in_version=deprecated_properties[item][
                "to_be_removed_in_version"
            ],
            old_name=item,
            new_name=deprecated_properties[item].get("new_property", item),
            new_attribute=deprecated_properties[item]["client_property"],
        )
        warnings.simplefilter("always", DeprecationWarning)
        warnings.warn(
            message=deprecation_message,
            category=DeprecationWarning,
            stacklevel=2,
        )
        warnings.simplefilter("default", DeprecationWarning)
        client_property = getattr(obj, deprecated_properties[item]["client_property"])
        return getattr(
            client_property, deprecated_properties[item].get("new_property", item)
        )

    raise AttributeError(
        "'{class_name}' has no attribute '{item}'".format(
            class_name=obj.__class__.__name__,
            item=item,
        )
    )


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
        if new_method is not None:
            new_method_name = new_method.__name__
            new_module_name = inspect.getmodule(new_method).__name__
        else:
            new_method_name, new_module_name = (None, None)

        deprecation_message = generate_method_deprecation_message(
            to_be_removed_in_version=to_be_removed_in_version,
            old_method_name=method.__name__,
            method_name=new_method_name,
            module_name=new_module_name,
        )

        @functools.wraps(method)
        def new_func(*args, **kwargs):
            warnings.simplefilter("always", DeprecationWarning)  # turn off filter
            warnings.warn(
                message=deprecation_message,
                category=DeprecationWarning,
                stacklevel=2,
            )
            warnings.simplefilter("default", DeprecationWarning)  # reset filter
            return method(*args, **kwargs)

        if new_method:
            # Here we copy the docstring from the specified replacement method (i.e., the method to be used in place of
            # the one we're marking as deprecated) where available to set within the deprecated method's docstring.
            # If the "new" method has no docstring, we use a value of "N/A".
            docstring_copy = (
                new_method.__doc__ if new_method.__doc__ is not None else "N/A"
            )
            if new_method.__doc__ is not None:
                new_func.__doc__ = """\
                    {message}
                    Docstring content from this method's replacement copied below:
                    {docstring_copy}
                    """.format(
                    message=deprecation_message,
                    docstring_copy=dedent(docstring_copy),
                )

        else:
            new_func.__doc__ = deprecation_message
        return new_func

    return decorator


def validate_list_of_strings_param(param_name, param_argument):
    """Validate that an argument is a list of strings.

    :param param_name: The name of the parameter being validated. Used in any resulting exception messages.
    :type param_name: str | unicode
    :param param_argument: The argument to validate.
    :type param_argument: list
    :return: True if the argument is validated, False otherwise.
    :rtype: bool
    """
    if param_argument is None:
        param_argument = []
    if isinstance(param_argument, str):
        param_argument = param_argument.split(",")
    if not isinstance(param_argument, list) or not all(
        isinstance(p, str) for p in param_argument
    ):
        error_msg = 'unsupported {param} argument provided "{arg}" ({arg_type}), required type: List[str]'
        raise exceptions.ParamValidationError(
            error_msg.format(
                param=param_name,
                arg=param_argument,
                arg_type=type(param_argument),
            )
        )


def list_to_comma_delimited(list_param):
    """Convert a list of strings into a comma-delimited list / string.

    :param list_param: A list of strings.
    :type list_param: list
    :return: Comma-delimited string.
    :rtype: str
    """
    if list_param is None:
        list_param = []
    return ",".join(list_param)


def get_token_from_env():
    """Get the token from env var, VAULT_TOKEN. If not set, attempt to get the token from, ~/.vault-token

    :return: The vault token if set, else None
    :rtype: str | None
    """
    token = os.getenv("VAULT_TOKEN")
    if not token:
        token_file_path = os.path.expanduser("~/.vault-token")
        if os.path.exists(token_file_path):
            with open(token_file_path, "r") as f_in:
                token = f_in.read().strip()

    if not token:
        return None

    return token


def comma_delimited_to_list(list_param):
    """Convert comma-delimited list / string into a list of strings

    :param list_param: Comma-delimited string
    :type list_param: str | unicode
    :return: A list of strings
    :rtype: list
    """
    if isinstance(list_param, list):
        return list_param
    if isinstance(list_param, str):
        return list_param.split(",")
    else:
        return []


def validate_pem_format(param_name, param_argument):
    """Validate that an argument is a PEM-formatted public key or certificate

    :param param_name: The name of the parameter being validate. Used in any resulting exception messages.
    :type param_name: str | unicode
    :param param_argument: The argument to validate
    :type param_argument: str | unicode
    :return: True if the argument is validate False otherwise
    :rtype: bool
    """

    def _check_pem(arg):
        arg = arg.strip()
        if not arg.startswith("-----BEGIN CERTIFICATE-----") or not arg.endswith(
            "-----END CERTIFICATE-----"
        ):
            return False
        return True

    if isinstance(param_argument, str):
        param_argument = [param_argument]

    if not isinstance(param_argument, list) or not all(
        _check_pem(p) for p in param_argument
    ):
        error_msg = (
            "unsupported {param} public key / certificate format, required type: PEM"
        )
        raise exceptions.ParamValidationError(error_msg.format(param=param_name))


def remove_nones(params):
    """Removes None values from optional arguments in a parameter dictionary.

    :param params: The dictionary of parameters to be filtered.
    :type params: dict
    :return: A filtered copy of the parameter dictionary.
    :rtype: dict
    """

    return {key: value for key, value in params.items() if value is not None}


def format_url(format_str, *args, **kwargs):
    """Creates a URL using the specified format after escaping the provided arguments.

    :param format_str: The URL containing replacement fields.
    :type format_str: str
    :param kwargs: Positional replacement field values.
    :type kwargs: list
    :param kwargs: Named replacement field values.
    :type kwargs: dict
    :return: The formatted URL path with escaped replacement fields.
    :rtype: str
    """

    def url_quote(maybe_str):
        # Special care must be taken for Python 2 where Unicode characters will break urllib quoting.
        # To work around this, we always cast to a Unicode type, then UTF-8 encode it.
        # Doing this is version agnostic and returns the same result in Python 2 or 3.
        unicode_str = six.text_type(maybe_str)
        utf8_str = unicode_str.encode("utf-8")
        return six.moves.urllib.parse.quote(utf8_str)

    escaped_args = [url_quote(value) for value in args]
    escaped_kwargs = {key: url_quote(value) for key, value in kwargs.items()}

    return format_str.format(*escaped_args, **escaped_kwargs)

class VaultError(Exception):
    def __init__(self, message=None, errors=None, method=None, url=None):
        if errors:
            message = ", ".join(errors)

        self.errors = errors
        self.method = method
        self.url = url

        super(VaultError, self).__init__(message)

    def __str__(self):
        return "{0}, on {1} {2}".format(self.args[0], self.method, self.url)


class InvalidRequest(VaultError):
    pass


class Unauthorized(VaultError):
    pass


class Forbidden(VaultError):
    pass


class InvalidPath(VaultError):
    pass


class RateLimitExceeded(VaultError):
    pass


class InternalServerError(VaultError):
    pass


class VaultNotInitialized(VaultError):
    pass


class VaultDown(VaultError):
    pass


class UnexpectedError(VaultError):
    pass


class BadGateway(VaultError):
    pass


class ParamValidationError(VaultError):
    pass

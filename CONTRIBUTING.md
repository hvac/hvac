# Contributing

Feel free to open pull requests with additional features or improvements!

## Testing

Integration tests will automatically start a Vault server in the background. Just make sure
the latest `vault` binary is available in your `PATH`.

1. [Install Vault](https://vaultproject.io/docs/install/index.html) or execute `VAULT_BRANCH=release scripts/install-vault-release.sh`
2. [Install Tox](http://tox.readthedocs.org/en/latest/install.html)
3. Run tests: `make test`

## Documentation

### Examples

Example code or general guides for methods in this module can be added under [docs/examples](docs/examples).

## Backwards Compatibility Breaking Changes

Due to the close connection between this module and HashiCorp Vault versions, breaking changes are sometimes required. This can also occur as part of code refactoring to enable improvements in the module generally. In these cases:

* A deprecation notice should be displayed to callers of the module until the minor revision +2. E.g., a notice added in version 0.6.2 could see the marked method / functionality removed in version 0.8.0.
* Breaking changes should be called out in the [CHANGELOG.md](CHANGELOG.md) for the affected version.

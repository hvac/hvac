# Contributing

Feel free to open issues and/or pull requests with additional features or improvements! For general questions about contributing to hvac that don't fit in the scope of a GitHub issue, and for any folks are interested in becoming a maintainer of hvac, please feel free to join our gitter chat room for discussions at [gitter.im/hvac/community](https://gitter.im/hvac/community): [![Gitter chat](https://badges.gitter.im/hvac/community.png)](https://gitter.im/hvac/community)

## Typical Devevelopment Environment Setup

```
virtualenv hvac-env
source hvac-env/bin/activate

git clone https://github.com/hvac/hvac.git
cd hvac
pip install -e .
```

## Testing

Integration tests will automatically start a Vault server in the background. Just make sure
the latest `vault` binary is available in your `PATH`.

1. [Install Vault](https://vaultproject.io/docs/install/index.html) or execute `tests/scripts/install-vault.sh`. Note: by default this script installs the OSS version of Vault. An enterprise trial version of the Vault binary is available for testing (but has an explicitly limited runtime). To run integration test cases requiring enterprise Vault, you can invoke the installation script with: `install-vault.sh <desired version> 'enterprise'`
2. Install requirements
```
cd hvac
pip install -r requirements.txt
```
3. Run tests: `make test`

## Updating Requirements

This project uses [pip-tool's](https://pypi.org/project/pip-tools/) `pip-compile` utility to manage its various requirements.
Any given requirements file can be manually updated by following the pip-compile comments at the top of the file. Alternatively, the `update-all-requirements` Makefile target can be used to update requirements across the board (this has a dependency on docker being available).

## Documentation

### Testing Docs

```
cd docs/
pip install -r requirements.txt
make doctest
```

### Examples

Example code or general guides for methods in this module can be added under [docs/usage](docs/usage). Any newly added or updated method in this module will ideally have a corresponding addition to these examples. New usage sections should also be added to the table of contents tracked in [docs/usage.rst](docs/usage.rst).

## Backwards Compatibility Breaking Changes

Due to the close connection between this module and HashiCorp Vault versions, breaking changes are sometimes required. This can also occur as part of code refactoring to enable improvements in the module generally. In these cases:

* A deprecation notice should be displayed to callers of the module until the minor revision +2. E.g., a notice added in version 0.6.2 could see the marked method / functionality removed in version 0.8.0.
* Breaking changes should be called out in the [CHANGELOG.md](CHANGELOG.md) for the affected version.

## Creating / Publishing Releases

- [ ] Checkout the `develop` branch:
  ```
  git checkout develop
  git pull
  ```
- [ ] Update the version number using [bumpversion](https://github.com/peritus/bumpversion). Releases typically just use the "patch" bumpversion option; but "minor" and "major" are available as needed as needed. This will also add an appropriate git commit for the new version.
  ```
  bumpversion --no-tag {patch|minor|major}
  ```
- [ ] Pull up the current draft [hvac release](https://github.com/hvac/hvac/releases/) and use the [release-drafter](https://github.com/toolmantim/release-drafter) generated release body to update [CHANGELOG.md](CHANGELOG.md). Then commit the changes:
  ```
  git commit CHANGELOG.md -m "Changelog updates for v$(grep -oP '(?<=current_version = ).*' .bumpversion.cfg)"
  ```
- [ ] Git push the updated develop branch (`git push`) and open a PR to rebase merge the develop branch into master:  [https://github.com/hvac/hvac/compare/master...develop](https://github.com/hvac/hvac/compare/master...develop). Ensure the PR has the "release" label applied and then merge it.

- [ ] Publish the draft release on GitHub: [https://github.com/hvac/hvac/releases](https://github.com/hvac/hvac/releases). Ensure the tag is set to the release name (e.g., vX.X.X) and the target is the master branch.
  NOTE: [release-drafter](https://github.com/toolmantim/release-drafter) sets the release name by default. If performing a minor or major update, these values will need to be manually updated before publishing the draft release subsequently.

# Contributing

Feel free to open pull requests with additional features or improvements!

## Testing

Integration tests will automatically start a Vault server in the background. Just make sure
the latest `vault` binary is available in your `PATH`.

1. [Install Vault](https://vaultproject.io/docs/install/index.html) or execute `VAULT_BRANCH=release tests/scripts/install-vault-release.sh`
2. [Install Tox](http://tox.readthedocs.org/en/latest/install.html)
3. Run tests: `make test`

## Updating Requirements

This project uses [pip-tool's](https://pypi.org/project/pip-tools/) `pip-compile` utility to manage its various requirements.
Any given requirements file can be manually updated by following the pip-compile comments at the top of the file. Alternatively, the `update-all-requirements` Makefile target can be used to update requirements across the board (this has a dependency on docker being available).

## Documentation

### Examples

Example code or general guides for methods in this module can be added under [docs/usage](docs/usage). Any newly added or updated method in this module will ideally have a corresponding addition to these examples. New usage sections should also be added to the table of contents tracked in [docs/usage.rst](docs/usage.rst).

## Backwards Compatibility Breaking Changes

Due to the close connection between this module and HashiCorp Vault versions, breaking changes are sometimes required. This can also occur as part of code refactoring to enable improvements in the module generally. In these cases:

* A deprecation notice should be displayed to callers of the module until the minor revision +2. E.g., a notice added in version 0.6.2 could see the marked method / functionality removed in version 0.8.0.
* Breaking changes should be called out in the [CHANGELOG.md](CHANGELOG.md) for the affected version.

## Package Publishing Checklist

The follow list uses version number `0.6.2`, this string should be updated to match the intended release version. It is based on this document: [https://gist.github.com/audreyr/5990987](https://gist.github.com/audreyr/5990987)

- [ ] Ensure your working directory is clear by running:
  ```
  make distclean
  ```
- [ ] Checkout the `develop` branch:
  ```
  git checkout develop
  git pull
  ```
- [ ] Update [CHANGELOG.md](CHANGELOG.md) with a list of the included changes. Those changes can be reviewed, and their associated GitHub PR number confirmed, via GitHub's pull request diff. E.g.: [https://github.com/hvac/hvac/compare/master...develop](https://github.com/hvac/hvac/compare/master...develop). Then commit the changes:
  ```
  git commit CHANGELOG.md -m 'Changelog updates for vX.X.X release'
  ```
- [ ] Update version number using [bumpversion](https://github.com/peritus/bumpversion). Releases typically just use the "patch" bumpversion option; but "minor" and "major" are available as needed as needed. This will also add an appropriate git commit and tag for the new version.
  ```
  bumpversion {patch|minor|major}
  ```
- [ ] Install the package again for local development, but with the new version number:
  ```
  python setup.py develop
  ```
- [ ] Run the tests and verify that they all pass:
  ```
  make test
  ```
- [ ] Invoke setup.py / setuptools via the "package" Makefile job to create the release version's sdist and wheel artifacts:
  ```
  make package
  ```

- [ ] Publish the sdist and wheel artifacts to [TestPyPI](https://packaging.python.org/guides/using-testpypi/) using [twine](https://pypi.org/project/twine/):
  ```
  twine upload --repository-url https://test.pypi.org/legacy/ dist/*.tar.gz dist/*.whl
  ```
- [ ] Check the TestPyPI project page to make sure that the README, and release notes display properly: [https://test.pypi.org/project/hvac/](https://test.pypi.org/project/hvac/)
- [ ] Test that the version is correctly listed and it pip installs (`mktmpenv` is available via the [virtualenvwrapper module](http://virtualenvwrapper.readthedocs.io/en/latest/install.html#shell-startup-file)) using the [TestPyPI](https://packaging.python.org/guides/using-testpypi/) repository (Note: installation will currently fail due to missing recent releases of `requests` on TestPyPI):
  ```
  mktmpenv
  pip install --no-cache-dir --index-url https://test.pypi.org/simple hvac==
  <verify releaes version shows up with the correct formatting in the resulting list>
  pip install --no-cache-dir --index-url https://test.pypi.org/simple hvac==0.6.2
  <verify hvac functionality>
  deactivate
  ```
- [ ] Create a **draft** GitHub release using the contents of the new release version's [CHANGELOG.md](CHANGELOG.md) content: https://github.com/hvac/hvac/releases/new
- [ ] Upload the sdist and whl files to the draft GitHub release as attached "binaries".
- [ ] Git push the updated develop branch (`git push`) and open a PR to merge the develop branch into master:  [https://github.com/hvac/hvac/compare/master...develop](https://github.com/hvac/hvac/compare/master...develop)

- [ ] Publish the sdist and wheel artifacts to [PyPI](https://pypi.org/) using [twine](https://pypi.org/project/twine/):
  ```
  twine upload dist/*.tar.gz dist/*.whl
  ```
- [ ] Check the PyPI project page to make sure that the README, and release notes display properly: [https://pypi.org/project/hvac/](https://pypi.org/project/hvac/)
- [ ] Test that the version is correctly listed and it pip installs (`mktmpenv` is available via the [virtualenvwrapper module](http://virtualenvwrapper.readthedocs.io/en/latest/install.html#shell-startup-file)) using the [TestPyPI](https://packaging.python.org/guides/using-testpypi/) repository:
  ```
  mktmpenv
  pip install --no-cache-dir hvac==
  <verify releaes version shows up with the correct formatting in the resulting list>
  pip install --no-cache-dir hvac==0.6.2
  <verify hvac functionality>
  deactivate
  ```

- [ ] Publish the draft release on GitHub: [https://github.com/hvac/hvac/releases](https://github.com/hvac/hvac/releases)

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

Example code or general guides for methods in this module can be added under [docs/examples](docs/examples). Any newly added or update method in this module will ideally have a corresponding addition to these examples.

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
- [ ] Checkout a working branch:
  ```
  git checkout -b master_v0-6-2
  ```
- [ ] Update [CHANGELOG.md](CHANGELOG.md) with a list of the included changes. Those changes can be reviewed, and their associated GitHub PR number confirmed, via GitHub's pull request diff using the previous version's tag. E.g.: [https://github.com/hvac/hvac/compare/v0.6.1...master](https://github.com/hvac/hvac/compare/v0.6.1...master)
- [ ] Commit the changelog changes:
  ```
  git add CHANGELOG.md
  git commit -S -m "Updates for upcoming release 0.6.2"
  ```
- [ ] Update version number using [bumpversion](https://github.com/peritus/bumpversion). This example is for the "patch" version but can also be "minor" or "major" as needed.
  ```
  bumpversion patch version
  ```
- [ ] Commit the version changes:
  ```
  git add version setup.cfg
  git commit -S -m "Bump patch version to $(cat version)"
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
- [ ] Push up the working branch (`git push`) and open a PR to merge the working branch into master:  [https://github.com/hvac/hvac/compare/master...master_v0-6-2](https://github.com/hvac/hvac/compare/master...master_v0-6-2)
- [ ] After merging the working branch into master, tag master with the release version and push that up as well:
  ```
  git checkout master
  git pull
  git tag "v$(cat version)"
  git push "v$(cat version)"
  ```

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
- [ ] Update the [hvac project on readthedocs.io](https://readthedocs.org/dashboard/hvac/versions/), set the "stable" version to the new release and ensure the new tag for the release version is set as "active".

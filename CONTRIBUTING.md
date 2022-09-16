# Contributing

Feel free to open issues and/or pull requests with additional features or improvements! For general questions about contributing to hvac that don't fit in the scope of a GitHub issue, and for any folks are interested in becoming a maintainer of hvac, please feel free to join our gitter chat room for discussions at: [gitter.im/hvac/community](https://gitter.im/hvac/community).

## Typical Development Environment Setup

HVAC uses poetry to manage dependencies, the virtual environment, and versioning. Instruction on how to install poetry can be found at: [python-poetry.org](https://python-poetry.org/docs/#installation).

```
git clone https://github.com/hvac/hvac.git
cd hvac

poetry install

# Run the following command on Linux
source $(poetry env info --path)/bin/activate
# Otherwise run this command on Windows
poetry shell
```

## Testing

Integration tests will automatically start a Vault server in the background. Just make sure
the latest `vault` binary is available in your `PATH`.

1. [Install Vault](https://vaultproject.io/docs/install/index.html)
2. Install requirements

```
cd hvac
poetry install
```

3. Enter the virtual environment
```
# Run the following command on Linux
source $(poetry env info --path)/bin/activate
# Otherwise run this command on Windows
poetry shell
```

4. Run tests: `make test`

## Updating Requirements

In order to update the versions for all dependencies, `poetry update` can be run before committing the updated poetry.lock file.

## Documentation

### Adding new dependencies

Should new dependencies need to be added, they can be simply added with Poetry. To add a dependency needed by HVAC run the following command.

```
poetry add {package_name}
```

If the dependency is only needed for development the `-D` flag can be used to mark the dependency as a development dependency.

```
poetry add -D {dev_package_name}
```

### Adding New Documentation Files

When adding documentation for an entirely new feature / class, it often makes sense to place the documentation in a new `.rst` file. After drafting the new file, be sure to add the file as an entry to at least one table of contents directive (e.g., `toctree`) to ensure it gets rendered and published on https://hvac.readthedocs.io/. As an example, the process for adding a new documentation file for a secrets engine related to Active Directory could involve:

1. Add a new file to `docs/usage/secrets_engines` with a name along the lines of `active_directory.rst`.
2. Update the `toctree` directive within `docs/usage/secrets_engines/index.rst` to add a line for `active_directory`
3. Verify the new file is being included and rendered as expected by running `make html` from the `docs/` subdirectory. You can then view the rendered HTML documentation, in a browser or otherwise, by opening `docs/_build/html/index.html`.

### Testing Docs

```
# Run the following command on Linux
source $(poetry env info --path)/bin/activate
# Otherwise run this command on Windows
poetry shell

cd docs/
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
- [ ] Update the version number using [Poetry](https://python-poetry.org/docs/). Releases typically just use the "patch" bumpversion option; but "minor" and "major" are available as needed. This will also add an appropriate git commit for the new version.

  ```
  poetry version {patch|minor|major}
  ```
- [ ] Pull up the current draft [hvac release](https://github.com/hvac/hvac/releases/) and use the [release-drafter](https://github.com/toolmantim/release-drafter) generated release body to update [CHANGELOG.md](CHANGELOG.md). Then commit the changes:

  ```
  git commit CHANGELOG.md -m "Changelog updates for v$(grep -oP '(?<=current_version = ).*' .bumpversion.cfg)"
  ```
- [ ] Git push the updated develop branch (`git push`) and open a PR to rebase merge the develop branch into main:  [https://github.com/hvac/hvac/compare/main...develop](https://github.com/hvac/hvac/compare/main...develop). Ensure the PR has the "release" label applied and then merge it.

- [ ] Publish the draft release on GitHub: [https://github.com/hvac/hvac/releases](https://github.com/hvac/hvac/releases). Ensure the tag is set to the release name (e.g., vX.X.X) and the target is the main branch.
  NOTE: [release-drafter](https://github.com/toolmantim/release-drafter) sets the release name by default. If performing a minor or major update, these values will need to be manually updated before publishing the draft release subsequently.

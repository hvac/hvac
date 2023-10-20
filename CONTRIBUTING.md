# Contributing

Feel free to open issues and/or pull requests with additional features or improvements! For general questions about contributing to hvac that don't fit in the scope of a GitHub issue, and for any folks are interested in becoming a maintainer of hvac, please feel free to join our gitter chat room for discussions at: [gitter.im/hvac/community](https://gitter.im/hvac/community).

## Typical Development Environment Setup

HVAC uses poetry to manage dependencies, the virtual environment, and versioning. Instruction on how to install poetry can be found at: [python-poetry.org](https://python-poetry.org/docs/#installation).

```
git clone https://github.com/hvac/hvac.git
cd hvac

poetry install --with dev

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
poetry install --with dev
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

If the dependency is only needed for development, add it to the `dev` group like so:

```
poetry add --group dev {dev_package_name}
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

### Preparing the release branch

Ensure your local `main` branch is up to date, and then checkout a new branch to create a release PR:

  ```
  git checkout main
  git pull
  # git pull upstream main
  git checkout -b release/vX.Y.Z
  ```

### Updating the version

We use the `poetry-bumpversion` plugin for bumping versions. Check the `poetry` documentation for [using plugins](https://python-poetry.org/docs/master/plugins/#using-plugins) for instructions on installing the plugin in your `poetry` environment.

`hvac` uses [semver](https://semver.org/) so be aware of whether the next version is a minor, major, or patch release.

Minor will be most common, but it will depend on the PRs that have been accepted. Ideally, all PRs are added to a milestone and we can refer to those to determine what the next version must be.

Update the version number in all the places that need to be updated:

```
poetry version {patch|minor|major}
```

**IMPORTANT:** if you do not see any line(s) in the output that look like `poetry_bumpversion: processed file <filename>` then you must install the `poetry-bumpversion` plugin. Without that, only `pyproject.toml` is updated, which is not correct.

Choose `minor`, `major`, or `patch` as appropriate.

Review the changed files (ensure all files listed in `[tool.poetry_bumpversion.file.*]` entries in `pyproject.toml` are modified), and commit the changes to the branch.

### Updating the changelog

Pull up the current draft [hvac release](https://github.com/hvac/hvac/releases/) and use the [release-drafter](https://github.com/toolmantim/release-drafter) generated release body to update [CHANGELOG.md](CHANGELOG.md). **Take note of header levels, which may differ between the draft and the changelog.**

⚠ **NOTE:** the changelog is written in markdown, but will be converted to reStructured Text (RST) for the docsite. Markdown supports nested formatting, but RST does not, and the conversion will not happen correctly. For example, in markdown we can write `**_this in bold and italics_**` but only one formatting will convert. While it didn't in the past, this should now fail (as a warning) in CI to bring it to our attention. Fix these by choosing a single formatting style for the selected text.

When the changelog looks good, commit it to the branch.

#### Handling announcements and deprecations

Release drafter is only aware of PRs. Deprecations or other announcements that are posted as issues or discussions, even if labeled appropriately, will not be included, and we must add these into the channgelog manually for now.

[Search for issues with the `deprecation` or `announcement` labels](https://github.com/hvac/hvac/issues?q=is%3Aissue+is%3Aopen+label%3Aannouncement%2Cdeprecation) to see if anything needs to be added.

If there were no PRs with these labels, release drafter will not have created the section header either. Use the following header:
- `📢 Deprecations / Announcements`
Ensure each entry has a link to the relevant GitHub issue/PR (see the other entries).

### Opening the release PR

Push the release branch (`git push`, with tracking if needed) and open a PR.
Ensure the PR has the `release` label applied and then squash & merge it after review and tests pass.

### Tag and release

Publish the draft release on GitHub: [https://github.com/hvac/hvac/releases](https://github.com/hvac/hvac/releases).
**Ensure the tag is set to the release name (e.g., `vX.Y.Z`) and the target is the `main` branch.**

  NOTE: [release-drafter](https://github.com/toolmantim/release-drafter) sets the release name by default. If performing a minor or major update, these values may need to be manually updated before publishing the draft release subsequently, if some PRs were not labeled to tell release drafter that they required a specific level bump.

Publishing the release will also create a tag, and this will trigger release to PyPI. Be sure to [check that workflow](https://github.com/hvac/hvac/actions/workflows/python-publish.yml) and the [`hvac` page on PyPI](https://pypi.org/project/hvac/) to ensure that it completes successfully.

# hvac

![Header image](https://raw.githubusercontent.com/hvac/hvac/master/docs/_static/hvac_logo_800px.png)

[HashiCorp](https://hashicorp.com/) [Vault](https://www.vaultproject.io) API client for Python 2.7/3.x

[![Travis CI](https://travis-ci.org/hvac/hvac.svg?branch=master)](https://travis-ci.org/hvac/hvac)
[![codecov](https://codecov.io/gh/hvac/hvac/branch/master/graph/badge.svg)](https://codecov.io/gh/hvac/hvac)
[![Documentation Status](https://readthedocs.org/projects/hvac/badge/)](https://hvac.readthedocs.io/en/latest/?badge=latest)
[![PyPI version](https://badge.fury.io/py/hvac.svg)](https://badge.fury.io/py/hvac)
[![Twitter - @python_hvac](https://img.shields.io/twitter/follow/python_hvac.svg?label=Twitter%20-%20@python_hvac&style=social?style=plastic)](https://twitter.com/python_hvac)

Tested against the latest release, HEAD ref, and 3 previous major versions (counting back from the latest release) of Vault. 
Currently supports Vault v0.10.4 or later.

## Installation

```console
pip install hvac
```

If you would like to be able to return parsed HCL data as a Python dict for methods that support it:

```console
pip install "hvac[parser]"
```



## Documentation

Additional documentation for this module available at: [hvac.readthedocs.io](https://hvac.readthedocs.io/en/stable/usage/index.html):

* [Getting Started](https://hvac.readthedocs.io/en/stable/overview.html#getting-started)
* [Usage](https://hvac.readthedocs.io/en/stable/usage/index.html)
* [Advanced Usage](https://hvac.readthedocs.io/en/stable/advanced_usage.html)
* [Source Reference / Autodoc](https://hvac.readthedocs.io/en/stable/source/index.html)
* [Contributing](https://hvac.readthedocs.io/en/stable/contributing.html)
* [Changelog](https://hvac.readthedocs.io/en/stable/changelog.html)

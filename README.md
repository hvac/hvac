# hvac

[HashiCorp](https://hashicorp.com/) [Vault](https://www.vaultproject.io) API client for Python 2/3

[![Travis CI](https://travis-ci.org/ianunruh/hvac.svg?branch=master)](https://travis-ci.org/ianunruh/hvac) [![Latest Version](https://img.shields.io/pypi/v/hvac.svg)](https://pypi.python.org/pypi/hvac/) [![Documentation Status](//readthedocs.org/projects/hvac/badge/?version=latest)](https://hvac.readthedocs.io/en/latest/?badge=latest)

Tested against Vault v0.1.2 and HEAD. Requires v0.1.2 or later.

## Getting started

### Installation

```bash
pip install hvac
```
or
```bash
pip install "hvac[parser]"
```
if you would like to be able to return parsed HCL data as a Python dict for methods that support it.

### Initialize the client

```python
import os

import hvac

# Using plaintext
client = hvac.Client()
client = hvac.Client(url='http://localhost:8200')
client = hvac.Client(url='http://localhost:8200', token=os.environ['VAULT_TOKEN'])

# Using TLS
client = hvac.Client(url='https://localhost:8200')

# Using TLS with client-side certificate authentication
client = hvac.Client(url='https://localhost:8200', cert=('path/to/cert.pem', 'path/to/key.pem'))

```

### Read and write to secret backends

```python
client.write('secret/foo', baz='bar', lease='1h')

print(client.read('secret/foo'))

client.delete('secret/foo')
```

### Authenticate using token auth backend

```python
# Token
client.token = 'MY_TOKEN'
assert client.is_authenticated() # => True
```

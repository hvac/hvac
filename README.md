# HVAC

[Hashicorp](https://hashicorp.com/) [Vault](https://www.vaultproject.io) API client for Python 2/3

[![Travis CI](https://travis-ci.org/ianunruh/hvac.svg?branch=master)](https://travis-ci.org/ianunruh/hvac) [![Latest Version](https://pypip.in/version/hvac/badge.svg)](https://pypi.python.org/pypi/hvac/)

## Getting started

### Installation

```bash
pip install hvac
```

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
client = hvac.Client(url='https://localhost:8200',
                     cert=('path/to/cert.pem', 'path/to/key.pem'))
```

### Read and write to secret backends

```python
client.write('secret/foo', baz='bar', lease='1h')

print(client.read('secret/foo'))

client.delete('secret/foo')
```

### Authenticate to different auth backends

```python
# App ID
client.auth_app_id('MY_APP_ID', 'MY_USER_ID')

# GitHub
client.auth_github('MY_GITHUB_TOKEN')

# LDAP, Username & Password
client.auth_ldap('MY_USERNAME', 'MY_PASSWORD')
client.auth_userpass('MY_USERNAME', 'MY_PASSWORD')

# TLS
client = Client(cert=('path/to/cert.pem', 'path/to/key.pem'))
client.auth_tls()

# Token
client.auth_token('MY_TOKEN')

# Non-default mount point (available on all auth types)
client.auth_userpass('MY_USERNAME', 'MY_PASSWORD', mount_point='CUSTOM_MOUNT_POINT')

# Logout
client.logout()
```

### Manage tokens

```python
token = client.create_token(policies=['root'], lease='1h')

current_token = client.lookup_token()
some_other_token = client.lookup_token('xxx')

client.revoke_token('xxx')
client.revoke_token('yyy', orphan=True)

client.revoke_token_prefix('zzz')

client.renew_token('aaa')
```

### Manipulate auth backends

```python
backends = client.list_auth_backends()

client.enable_auth_backend('userpass', mount_point='customuserpass')
client.disable_auth_backend('github')
```

### Manipulate secret backends

```python
backends = client.list_secret_backends()

client.enable_secret_backend('aws', mount_point='aws-us-east-1')
client.disable_secret_backend('mysql')

client.remount_secret_backend('aws-us-east-1', 'aws-east')
```

### Manipulate policies

```python
policies = client.list_policies() # => ['root']

policy = """
path "sys" {
  policy = "deny"
}

path "secret" {
  policy = "write"
}

path "secret/foo" {
  policy = "read"
}
"""

client.set_policy('myapp', policy)

client.delete_policy('oldthing')
```

### Manipulate audit backends

```
backends = client.list_audit_backends()

options = {
    'path': '/tmp/vault.log',
    'log_raw': True,
}

client.enable_audit_backend('file', options=options, name='somefile')
client.disable_audit_backend('oldfile')
```

### Initialize and seal/unseal

```python
print(client.is_initialized()) # => False

shares = 5
threshold = 3

result = client.initialize(shares, threshold)

root_token = result['root_token']
keys = result['keys']

print(client.is_initialized()) # => True

print(client.is_sealed()) # => True

# unseal with individual keys
client.unseal(keys[0])
client.unseal(keys[1])
client.unseal(keys[2])

# unseal with multiple keys until threshold met
client.unseal_multi(keys)

print(client.is_sealed()) # => False

client.seal()

print(client.is_sealed()) # => True
```

## Testing

Integration tests will automatically start a Vault server in the background. Just make sure
the latest `vault` binary is available in your `PATH`.

1. [Install Vault](https://vaultproject.io/docs/install/index.html)
2. [Install Tox](http://tox.readthedocs.org/en/latest/install.html)

## Contributing

Feel free to open pull requests with additional features or improvements!

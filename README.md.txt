# python-vaultclient

Python 2/3 client for the [Hashicorp](https://hashicorp.com/) [Vault](https://www.vaultproject.io) secret management tool.

[![Travis CI](https://travis-ci.org/ianunruh/python-vaultclient.svg?branch=master)](https://travis-ci.org/ianunruh/python-vaultclient)

## Usage

```python

import vault
```

### authentication examples

#### token
```python

client = vault.Client(url='https://<your-vault-server>', token='<your_token>')
```

#### app-id
```python

client = vault.Client(url='https://<your-vault-server>')

client.auth_app_id('<app_id>', '<user_id>')
```

#### username / password
```python

client = vault.Client(url='https://<your-vault-server>')

client.auth_userpass('<username>', '<password>')
```
### secrets interactions

#### generic secret read/write/delete
```python

client.write('secret/foo', baz='bar')

client.read('secret/foo')

client.delete('secret/foo')
```

## Testing

1. [Install and start the Vault dev server](https://vaultproject.io/intro/getting-started/install.html)
2. Load the dev token into an environment variable

        export VAULT_TOKEN=$(cat ~/.vault-token)

3. [Install and run tox](http://tox.readthedocs.org/en/latest/install.html)

## Contributing

Feel free to open pull requests with additional features or improvements!

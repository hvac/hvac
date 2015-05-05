# python-vaultclient

Python 2/3 client for the [Hashicorp](https://hashicorp.com/) [Vault](https://www.vaultproject.io) secret management tool.

## Usage

```python
import os

import vault

client = vault.Client(
    url='https://localhost:8200',
    token=os.environ['VAULT_TOKEN'])

client.write('secret/foo', baz='bar', lease='1h')

print(client.read('secret/foo'))

client.delete('secret/foo')
```

## Testing

1. [Install and start the Vault dev server](https://vaultproject.io/intro/getting-started/install.html)
2. Load the dev token into an environment variable

        export VAULT_TOKEN=$(cat ~/.vault-token)

3. [Install and run tox](http://tox.readthedocs.org/en/latest/install.html)

## Contributing

Feel free to open pull requests with additional features or improvements!

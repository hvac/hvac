import os

from vault import Client

def test_generic_secret_backend():
    client = Client(
        token=os.environ['VAULT_TOKEN'],
        url='http://localhost:8200',
    )

    client.write('secret/foo', zap='zip')
    result = client.read('secret/foo')

    assert result['data']['zap'] == 'zip'

    client.delete('secret/foo')

import os

from nose.tools import *

from vault import Client, exceptions

def create_client():
    return Client(
        token=os.environ['VAULT_TOKEN'],
        url='http://localhost:8200',
    )

def test_generic_secret_backend():
    client = create_client()

    client.write('secret/foo', zap='zip')
    result = client.read('secret/foo')

    assert result['data']['zap'] == 'zip'

    client.delete('secret/foo')

@raises(exceptions.InvalidPath)
def test_invalid_path():
    client = create_client()
    client.read('secret/I/do/not/exist')

@raises(exceptions.InternalServerError)
def test_internal_server_error():
    client = create_client()
    client.read('handler/does/not/exist')

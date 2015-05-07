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

def test_auth_backend_manipulation():
    client = create_client()

    assert 'github/' not in client.list_auth_backends()

    client.enable_auth_backend('github')
    assert 'github/' in client.list_auth_backends()

    client.disable_auth_backend('github')
    assert 'github/' not in client.list_auth_backends()

def test_auth_token_manipulation():
    client = create_client()

    result = client.create_token(lease='1h')
    assert result['auth']['client_token']

    lookup = client.lookup_token(result['auth']['client_token'])
    assert result['auth']['client_token'] == lookup['data']['id']

    renew = client.renew_token(lookup['data']['id'])
    assert result['auth']['client_token'] == renew['auth']['client_token']

    client.revoke_token(lookup['data']['id'])

    try:
        lookup = client.lookup_token(result['auth']['client_token'])
        assert False
    except exceptions.InvalidPath:
        assert True

def test_userpass_auth():
    client = create_client()

    client.enable_auth_backend('userpass')

    client.write('auth/userpass/users/testuser', password='testpass', policies='root')

    result = client.auth_userpass('testuser', 'testpass')

    client.disable_auth_backend('userpass')

def test_app_id_auth():
    client = create_client()

    client.enable_auth_backend('app-id')

    client.write('auth/app-id/map/app-id/foo', value='root')
    client.write('auth/app-id/map/user-id/bar', value='foo')

    result = client.auth_app_id('foo', 'bar')

    client.disable_auth_backend('app-id')

@raises(exceptions.InvalidPath)
def test_invalid_path():
    client = create_client()
    client.read('secret/I/do/not/exist')

@raises(exceptions.InternalServerError)
def test_internal_server_error():
    client = create_client()
    client.read('handler/does/not/exist')

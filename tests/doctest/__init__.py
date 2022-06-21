#!/usr/bin/env python
import logging
import os
from time import sleep

from requests_mock.mocker import Mocker

from tests import utils as test_utils
from tests.utils.mock_ldap_server import MockLdapServer
from tests.utils.server_manager import ServerManager


def doctest_global_setup():
    client = test_utils.create_client()
    manager = ServerManager(
        config_paths=[test_utils.get_config_file_path("vault-doctest.hcl")],
        client=client,
    )
    manager.start()
    manager.initialize()
    manager.unseal()

    mocker = Mocker(real_http=True)
    mocker.start()

    auth_method_paths = [
        f"ldap/login/{MockLdapServer.ldap_user_name}",
    ]
    for auth_method_path in auth_method_paths:
        mock_url = f"https://127.0.0.1:8200/v1/auth/{auth_method_path}"
        mock_response = {
            "auth": {
                "client_token": manager.root_token,
                "accessor": "0e9e354a-520f-df04-6867-ee81cae3d42d",
                "policies": ["default"],
                "lease_duration": 2764800,
                "renewable": True,
            },
        }
        mocker.register_uri(
            method="POST",
            url=mock_url,
            json=mock_response,
        )

    client.token = manager.root_token
    os.environ["VAULT_TOKEN"] = manager.root_token
    os.environ["REQUESTS_CA_BUNDLE"] = test_utils.get_config_file_path(
        "server-cert.pem"
    )
    os.environ["LDAP_USERNAME"] = MockLdapServer.ldap_user_name
    os.environ["LDAP_PASSWORD"] = MockLdapServer.ldap_user_password
    os.environ["AWS_LAMBDA_FUNCTION_NAME"] = "hvac-lambda"
    os.environ.setdefault("LDAP_PASSWORD", MockLdapServer.ldap_user_password)

    if "secret/" not in client.sys.list_mounted_secrets_engines()["data"]:
        client.sys.enable_secrets_engine(
            backend_type="kv",
            path="secret",
            options=dict(version=2),
        )
        attempts = 0
        while (
            attempts < 25
            and "secret/" not in client.sys.list_mounted_secrets_engines()["data"]
        ):
            attempts += 1
            logging.debug(
                "Waiting 1 second for KV V2 secrets engine under path {path} to become available...".format(
                    path="secret",
                )
            )
            sleep(1)

    return manager, mocker

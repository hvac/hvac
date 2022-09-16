#!/usr/bin/env python
from threading import Thread

import requests
import logging
from werkzeug.serving import make_server

from tests.utils import get_free_port

from tests.utils.mock_oauth_provider.app import create_app

logger = logging.getLogger(__name__)


class MockOauthProviderServerThread(Thread):
    def __init__(self, app_config=None, address="localhost", port="80"):
        Thread.__init__(self)
        self.address = address
        self.server_port = get_free_port()
        if app_config is None:
            app_config = {
                "SECRET_KEY": "secret",
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            }
        app_config.update(
            {
                "OAUTH2_JWT_ISS": "http://{address}:{port}/oauth".format(
                    address=self.address, port=self.server_port
                ),
            }
        )
        app = create_app(app_config)
        self.srv = make_server("127.0.0.1", self.server_port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    @property
    def url(self):
        return "http://{address}:{port}".format(
            address=self.address,
            port=self.server_port,
        )

    def run(self):
        logger.info("starting server")
        self.srv.serve_forever()

    def shutdown(self):
        self.srv.shutdown()


def create_user_session_and_client(
    server_url,
    oauth_redirect_uri,
    oauth_username="hvac-oauth-user",
    oauth_client_name="hvac-integration-tests",
    oauth_client_uri="https://python-hvac.org",
):
    # Persist our "user" session in between requests
    oauth_session = requests.Session()

    # Create our auth user
    create_user_response = oauth_session.post(
        url=f"{server_url}/api/user",
        data=dict(
            username=oauth_username,
        ),
    )
    create_user = create_user_response.json()
    logger.debug("create_user_response:\n%s\n" % create_user)

    # Set up the auth client details
    create_client_response = oauth_session.post(
        url=f"{server_url}/api/create_client",
        data=dict(
            client_name=oauth_client_name,
            client_uri=oauth_client_uri,
            scope="openid profile",
            redirect_uris=oauth_redirect_uri,
            grant_types="authorization_code",
            response_types="code",
            token_endpoint_auth_method="client_secret_basic",
        ),
    )
    client = create_client_response.json()
    logger.debug("create_client_data:\n%s\n" % client)
    return {
        "session": oauth_session,
        "client_id": client["client_id"],
        "client_secret": client["client_secret"],
        "discovery_url": f"{server_url}/oauth",
    }


if __name__ == "__main__":
    # Set up our test oidc provider / server's configuration and start it
    server = MockOauthProviderServerThread()
    server.start()

    # Persist our "user" session in between requests
    oauth_session = requests.Session()

    # Generic inputs
    oauth_username = "hvac-oauth-user"
    oauth_client_name = "hvac-integration-tests"
    oauth_client_uri = "https://python-hvac.org"
    oauth_redirect_uri = "https://localhost:8200/jwt-test/oidc/callback"

    # Unauthorized GET to the user API route
    unauth_get_response = oauth_session.get(f"{server.url}/api/user")
    logger.debug(
        "Unauthorized GET to the user API route:\n%s\n" % unauth_get_response.json()
    )

    # Create our user
    create_user_response = oauth_session.post(
        url=f"{server.url}/api/user",
        data=dict(
            username=oauth_username,
        ),
    )
    create_user = create_user_response.text
    logger.debug("create_user_response:\n%s\n" % create_user)

    # Create a client
    create_client_response = oauth_session.post(
        url=f"{server.url}/api/create_client",
        data=dict(
            client_name=oauth_client_name,
            client_uri=oauth_client_uri,
            scope="openid profile",
            redirect_uris=oauth_redirect_uri,
            grant_types="authorization_code",
            response_types="code",
            token_endpoint_auth_method="client_secret_basic",
        ),
    )
    client = create_client_response.json()
    logger.debug("create_client_data:\n%s\n" % client)

    # Authorized GET to the user API route after creating a client
    auth_get_response = oauth_session.get(f"{server.url}/api/user")
    logger.debug(
        "Authorized GET to the user API route after creating a client:\n%s\n"
        % auth_get_response.json()
    )

    authorize_response = oauth_session.get(
        url=f"{server.url}/oauth/authorize",
        data=dict(
            client_id=client["client_id"],
            scope="openid profile",
            response_type="code",
            nonce="abc",
        ),
    )
    # authorization = authorize_response.json()
    authorization = authorize_response.text
    logger.debug("authorize_response:\n%s\n" % authorization)

    # Finally stop our test oidc provider / server
    server.shutdown()

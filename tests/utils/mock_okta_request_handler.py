#!/usr/bin/env python
import json
import logging
from http.server import BaseHTTPRequestHandler


class MockOktaRequestHandler(BaseHTTPRequestHandler):
    """Small HTTP server used to mock out certain Okta API routes that vault requests in the Okta auth method."""

    def do_GET(self):
        """Dispatch GET requests to associated mock Okta 'handlers'."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        logging.debug(self.headers)
        return
        if self.path == "/user":
            self.do_user()
        elif self.path == "/user/orgs?per_page=100":
            self.do_organizations_list()
        elif self.path == "/user/teams?per_page=100":
            self.do_team_list()
        return

    # def log_message(self, format, *args):
    #     """Squelch any HTTP logging."""
    #     return

    def do_user(self):
        """Return the bare minimum Okta user data needed for Vault's Okta auth method."""
        response = {
            "login": "hvac-dude",
            "id": 1,
        }

        self.wfile.write(json.dumps(response).encode())

    def do_organizations_list(self):
        """Return the bare minimum Okta organization data needed for Vault's Okta auth method.

        Only returns data if the request Authorization header has a contrived Okta token value of "valid-token".
        """
        response = []
        if self.headers.get("Authorization") == "Bearer valid-token":
            response.append(
                {
                    "login": "hvac",
                    "id": 1,
                }
            )

            self.wfile.write(json.dumps(response).encode())

    def do_team_list(self):
        """Return the bare minimum Okta team data needed for Vault's Okta auth method.

        Only returns data if the request Authorization header has a contrived Okta token value of "valid-token".
        """
        response = []
        if self.headers.get("Authorization") == "Bearer valid-token":
            response.append(
                {
                    "name": "hvac-team",
                    "slug": "hvac-team",
                    "organization": {
                        "id": 1,
                    },
                }
            )
        self.wfile.write(json.dumps(response).encode())

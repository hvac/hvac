#!/usr/bin/env python
import json
import re

from http.server import BaseHTTPRequestHandler


class MockGithubRequestHandler(BaseHTTPRequestHandler):
    """Small HTTP server used to mock out certain GitHub API routes that vault requests in the github auth method."""

    def do_GET(self):
        """Dispatch GET requests to associated mock GitHub 'handlers'."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if "/orgs/" in self.path:
            org = re.match(r"\/orgs\/(?P<org>\S+)", self.path)["org"]
            self.do_organization(org)
        elif self.path == "/user":
            self.do_user()
        elif self.path == "/user/orgs?per_page=100":
            self.do_organizations_list()
        elif self.path == "/user/teams?per_page=100":
            self.do_team_list()
        return

    def log_message(self, format, *args):
        """Squelch any HTTP logging."""
        return

    def do_user(self):
        """Return the bare minimum GitHub user data needed for Vault's github auth method."""
        response = {
            "login": "hvac-dude",
            "id": 1,
        }

        self.wfile.write(json.dumps(response).encode())

    def do_organizations_list(self):
        """Return the bare minimum GitHub organization data needed for Vault's github auth method.

        Only returns data if the request Authorization header has a contrived github token value of "valid-token".
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

    def do_organization(self, org):
        response = {
            "login": org,
            "id": 1,
        }
        self.wfile.write(json.dumps(response).encode())

    def do_team_list(self):
        """Return the bare minimum GitHub team data needed for Vault's github auth method.

        Only returns data if the request Authorization header has a contrived github token value of "valid-token".
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

import logging
import time

import jwcrypto.jwk as jwk
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from flask import Blueprint, jsonify, request, session, url_for
from werkzeug.security import gen_salt

from tests.utils import get_config_file_path
from tests.utils.mock_oauth_provider.models import OAuth2Client, User, db
from tests.utils.mock_oauth_provider.oauth2 import authorization, require_oauth

logger = logging.getLogger(__name__)
bp = Blueprint("mock-oauth-provider", "home")


def current_user():
    if "id" in session:
        uid = session["id"]
        return User.query.get(uid)
    return None


@bp.route("/api/user", methods=("GET", "POST"))
def user():
    user = current_user()

    if request.method == "POST":
        username = request.form.get("username")
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session["id"] = user.id

    clients = []
    if user:
        clients = OAuth2Client.query.filter_by(user=user).all()

    response = {
        "user": user.as_dict() if user else None,
        "clients": {c.client_metadata["client_name"]: c.as_dict() for c in clients},
    }
    return jsonify(response)


@bp.route("/api/create_client", methods=["POST"])
def create_client():
    user = current_user()
    if not user:
        response = jsonify(
            {
                "message": "Unauthorized, no active user session found",
            }
        )
        return response, 401

    form = request.form
    client_id = gen_salt(24)
    client = OAuth2Client(client_id=client_id, user_id=user.id)
    # Mixin doesn't set the issue_at date
    client.client_id_issued_at = int(time.time())
    if client.token_endpoint_auth_method == "none":
        client.client_secret = ""
    else:
        client.client_secret = gen_salt(48)

    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": form["grant_types"],
        "redirect_uris": form["redirect_uris"],
        "response_types": form["response_types"],
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"],
    }
    client.set_client_metadata(client_metadata)
    db.session.add(client)
    db.session.commit()
    return jsonify(client.as_dict())


@bp.route("/oauth/.well-known/openid-configuration", methods=["GET"])
def well_known():
    base_url = request.host_url.rstrip("/")
    response = {
        "issuer": f"{base_url}/oauth",
        "authorization_endpoint": "{url}{authorize}".format(
            url=base_url, authorize=url_for(".authorize")
        ),
        "token_endpoint": "{url}{issue}".format(
            url=base_url, issue=url_for(".issue_token")
        ),
        "jwks_uri": "{url}{get_keys}".format(
            url=base_url, get_keys=url_for(".get_keys")
        ),
    }
    return jsonify(response)


@bp.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    user = current_user()
    if request.method == "GET":
        try:
            logger.debug("get_consent_grant for user: %s" % user)
            grant = authorization.get_consent_grant(end_user=user)
            logger.debug(f"grant for user {user}: {grant}")
        except OAuth2Error as error:
            return jsonify(dict(error.get_body()))
        return jsonify(
            {
                "requesting_client": grant.client.client_name,
                "requested_scope": grant.request.scope,
                "user": user.username,
            }
        )
    if not user and "username" in request.form:
        username = request.form.get("username")
        user = User.query.filter_by(username=username).first()
    if request.form["confirm"]:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route("/oauth/token", methods=["POST"])
def issue_token():
    return authorization.create_token_response()


@bp.route("/oauth/keys")
def get_keys():
    with open(get_config_file_path("oidc_private.pem"), "rb") as fh:
        signing_key = jwk.JWK.from_pem(fh.read())._public_params()
    return jsonify(
        {
            "keys": [
                signing_key,
            ]
        }
    )


@bp.route("/api/me")
@require_oauth("profile")
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)

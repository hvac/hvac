import os
from flask import Flask
from tests.utils.mock_oauth_provider.models import db
from tests.utils.mock_oauth_provider.oauth2 import config_oauth
from tests.utils.mock_oauth_provider.routes import bp


def create_app(config=None):
    app = Flask(__name__)

    # load default configuration
    app.config.from_object("tests.utils.mock_oauth_provider.settings")

    # load environment configuration
    if "WEBSITE_CONF" in os.environ:
        app.config.from_envvar("WEBSITE_CONF")

    # load app specified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith(".py"):
            app.config.from_pyfile(config)

    setup_app(app)
    return app


def setup_app(app):
    db.init_app(app)

    # Create tables if they do not exist already
    with app.app_context():
        db.create_all()

    config_oauth(app)
    app.register_blueprint(bp, url_prefix="")

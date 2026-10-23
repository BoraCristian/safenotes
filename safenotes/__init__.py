"""SafeNotes - a small notes app built to show secure web development practices."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, render_template
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db, security
from .config import load_config

__version__ = "0.1.0"

ERROR_TITLES = {
    400: "Bad request",
    401: "Sign in required",
    403: "Not allowed",
    404: "Not found",
    405: "Not allowed",
    413: "File too large",
    429: "Too many requests",
    500: "Something went wrong",
}


def create_app(overrides: dict | None = None, instance_path: str | None = None) -> Flask:
    app = Flask(__name__, instance_path=instance_path, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.update(load_config(Path(app.instance_path), overrides))
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

    if app.config["TRUSTED_PROXIES"]:
        n = app.config["TRUSTED_PROXIES"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

    db.init_app(app)
    security.init_app(app)

    from . import auth, notes
    app.register_blueprint(auth.bp)
    app.register_blueprint(notes.bp)

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        code = exc.code or 500
        # show a message only when our code passed one to abort(); Werkzeug's default texts are not shown
        message = exc.description if exc.description != type(exc).description else None
        return render_template("error.html", code=code, title=ERROR_TITLES.get(code, "Error"), message=message), code

    @app.errorhandler(Exception)
    def unhandled(exc: Exception):
        # log the details server-side, show the user nothing internal (A05: no stack traces)
        app.logger.exception("Unhandled error")
        return render_template("error.html", code=500, title=ERROR_TITLES[500], message=None), 500

    if not app.config.get("TESTING"):
        logging.basicConfig(level=logging.INFO)
        if app.config["ENV_NAME"] != "production" and "SAFENOTES_SECRET_KEY" not in os.environ:
            app.logger.warning("SAFENOTES_SECRET_KEY not set: using a random key, sessions reset on restart")
    return app
